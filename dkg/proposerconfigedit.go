// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package dkg

import (
	"context"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"google.golang.org/protobuf/proto"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
	dkgpb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
	"github.com/obolnetwork/charon/p2p"
)

const (
	// editProtocolID is the request/response protocol exchanging the proposer config edit round messages.
	editProtocolID protocol.ID = "/charon/proposerconfig/1.0.0"
	// maxEditMsgSize caps a round message, it fits the documents of tens of thousands of validators.
	maxEditMsgSize = 16 << 20
	// maxEditRequestSize caps a request, which only carries the round.
	maxEditRequestSize = 1 << 10
	// relayProbeTimeout bounds the reservation probe of a single relay.
	relayProbeTimeout = 10 * time.Second
	// relayResolveTimeout bounds the wait for a relay's address to resolve before probing it.
	relayResolveTimeout = time.Minute
)

const (
	editRoundCurrent  uint32 = 1
	editRoundProposal uint32 = 2
)

// ProposerConfigEditConfig configures a proposer config edit ceremony. DKGConfig.Timeout bounds the wait
// for operators to join and DKGConfig.P2P.Relays are the relays, which must not serve this node's charon run.
type ProposerConfigEditConfig struct {
	DKGConfig          Config
	LockFilePath       string
	PrivateKeyPath     string
	ProposerConfigFile string
	OverridesFile      string
	Delta              proposerconfig.Delta
	// ParticipatingENRs lists the operators running the ceremony, all of them if empty.
	ParticipatingENRs []string
}

// ProposerConfigEditResult is the outcome of a successful proposer config edit ceremony.
type ProposerConfigEditResult struct {
	Revision  uint64
	Hash      [32]byte
	Signers   int
	Operators int
	// Adopted is true if this node's file was behind and a peer's signed revision was used as the base.
	Adopted bool
}

// RunProposerConfigEdit runs the proposer config edit ceremony: the participating operators agree on the
// edited document, sign it, and each writes the next revision with the collected signatures, archiving
// the previous file.
func RunProposerConfigEdit(ctx context.Context, conf ProposerConfigEditConfig) (ProposerConfigEditResult, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ctx = log.WithTopic(ctx, "edit")

	lockPtr, err := LoadAndVerifyClusterLock(ctx, conf.LockFilePath, conf.DKGConfig.ExecutionEngineAddr, conf.DKGConfig.NoVerify)
	if err != nil {
		return ProposerConfigEditResult{}, errors.Wrap(err, "load cluster lock")
	}

	lock := *lockPtr

	key, err := LoadPrivKey(conf.PrivateKeyPath)
	if err != nil {
		return ProposerConfigEditResult{}, err
	}

	self, err := p2p.PeerIDFromKey(key.PubKey())
	if err != nil {
		return ProposerConfigEditResult{}, err
	}

	nodeIdx, err := lock.NodeIdx(self)
	if err != nil {
		return ProposerConfigEditResult{}, errors.Wrap(err, "private key not matching any operator in the cluster lock")
	}

	peers, err := participants(lock, conf.ParticipatingENRs, self)
	if err != nil {
		return ProposerConfigEditResult{}, err
	}

	base, onDisk, err := loadEditBase(ctx, lock, nodeIdx, conf.ProposerConfigFile, conf.OverridesFile)
	if err != nil {
		return ProposerConfigEditResult{}, err
	}

	// The file loaded at start, nil if absent; the write step checks it is still the one on disk.
	var disk *proposerconfig.Document

	if onDisk {
		loaded := base // A copy, base is replaced on adoption.
		disk = &loaded
	}

	proposedDoc, err := editProposal(lock, base, conf.Delta)
	if err != nil {
		return ProposerConfigEditResult{}, err
	}

	logEditDiff(ctx, lock, base, proposedDoc)

	err = probeRelays(ctx, conf.DKGConfig.P2P.Relays, lock, self)
	if err != nil {
		return ProposerConfigEditResult{}, err
	}

	if conf.DKGConfig.Timeout > 0 {
		var cancelTimeout context.CancelFunc

		ctx, cancelTimeout = context.WithTimeout(ctx, conf.DKGConfig.Timeout)
		defer cancelTimeout()
	}

	p2pNode, shutdown, err := setupP2P(ctx, key, relayOnlyConfig(conf.DKGConfig), peers, lock.LockHash, lock.UUID)
	if err != nil {
		return ProposerConfigEditResult{}, err
	}
	defer shutdown()

	ex := newEditExchange(p2pNode, peers)

	peerIDs, _ := buildPeerMap(peers)

	log.Info(ctx, "Waiting for operators to join the proposer config edit")

	stepSync, stopSync, fatalErr, err := startSyncProtocol(ctx, p2pNode, key, lock.LockHash, peerIDs, cancel,
		conf.DKGConfig.TestConfig, conf.DKGConfig.Nickname)
	if err != nil {
		return ProposerConfigEditResult{}, err
	}

	log.Info(ctx, "All participating operators connected", z.Int("operators", len(peerIDs)))

	// fatalOr returns the recorded fatal sync failure if any, else err.
	fatalOr := func(err error) error {
		if fatal := fatalErr(); fatal != nil {
			return fatal
		}

		return err
	}

	// failInStep fails on an outcome every participant reaches on the same messages, after the shutdown
	// handshake so peers can still fetch this node's message before it goes away.
	failInStep := func(err error) (ProposerConfigEditResult, error) {
		if serr := stopSync(ctx); serr != nil {
			log.Debug(ctx, "Proposer config edit shutdown after failure", z.Err(serr))
		}

		return ProposerConfigEditResult{}, err
	}

	otherNodesIDs := slices.DeleteFunc(slices.Clone(peerIDs), func(pID peer.ID) bool { return pID == self })
	allNodesNames := participantNames(peerIDs)

	ex.start(otherNodesIDs)

	// Round 1: exchange currentRevision documents, adopting a higher signed revision.
	currentRevision, err := proposerconfig.Marshal(base)
	if err != nil {
		return ProposerConfigEditResult{}, err
	}

	ex.prepare(&dkgpb.MsgProposerConfigEdit{Round: editRoundCurrent, CurrentRevision: currentRevision, Participants: allNodesNames})

	log.Info(ctx, "Round 1: exchanging the proposer config revisions found locally", z.U64("local_revision", base.Revision))

	msgs, err := ex.exchange(ctx, stepSync, editRoundCurrent)
	if err != nil {
		return ProposerConfigEditResult{}, fatalOr(err)
	}

	adoptedDoc, from, adopted, err := resolveEditBase(ctx, lock, nodeIdx.PeerIdx, base, allNodesNames, msgs)
	if err != nil {
		return failInStep(err)
	}

	if adopted {
		log.Info(ctx, fmt.Sprintf("Adopted signed revision %d from operator %d, local file was at revision %d", adoptedDoc.Revision, from, base.Revision))

		base = adoptedDoc

		proposedDoc, err = editProposal(lock, base, conf.Delta)
		if err != nil {
			return ProposerConfigEditResult{}, errors.Wrap(err, "apply change to adopted proposer config")
		}

		logEditDiff(ctx, lock, base, proposedDoc)
	} else {
		log.Info(ctx, "Round 1 done: no operator holds a newer signed revision, proposing from the local one")
	}

	// Round 2: exchange signed proposals, which must all be equal.
	proposalJSON, err := proposerconfig.Marshal(proposedDoc)
	if err != nil {
		return ProposerConfigEditResult{}, err
	}

	sig, err := proposerconfig.Sign(proposedDoc, key)
	if err != nil {
		return ProposerConfigEditResult{}, err
	}

	ex.prepare(&dkgpb.MsgProposerConfigEdit{Round: editRoundProposal, Proposal: proposalJSON, Signature: sig})

	log.Info(ctx, "Round 2: exchanging the signed proposals", z.U64("revision", proposedDoc.Revision))

	msgs, err = ex.exchange(ctx, stepSync, editRoundProposal)
	if err != nil {
		return ProposerConfigEditResult{}, fatalOr(err)
	}

	sigs, err := checkEditProposals(lock, proposedDoc, msgs)
	if err != nil {
		return failInStep(err)
	}

	sigs = append(sigs, proposerconfig.Signature{Operator: nodeIdx.PeerIdx, Signature: sig})

	log.Info(ctx, "Round 2 done: all proposals match and their signatures verify", z.Int("signatures", len(sigs)))

	doc, err := writeEditResult(lock, nodeIdx, conf.ProposerConfigFile, proposedDoc, sigs, disk)
	if err != nil {
		return ProposerConfigEditResult{}, err
	}

	hash, err := doc.Hash()
	if err != nil {
		return ProposerConfigEditResult{}, err
	}

	log.Info(ctx, "Proposer config updated", z.U64("revision", doc.Revision), z.Hex("hash", hash[:]), z.Any("signers", doc.SignerIndexes()))

	// The file is written and verifies on its own, so a failed handshake is not a failed edit.
	if err := stopSync(ctx); err != nil {
		log.Warn(ctx, "Proposer config edit shutdown handshake failed", fatalOr(err))
	}

	select {
	case <-ctx.Done():
	case <-time.After(conf.DKGConfig.ShutdownDelay):
	}

	return ProposerConfigEditResult{
		Revision:  doc.Revision,
		Hash:      hash,
		Signers:   len(doc.Signatures),
		Operators: len(lock.Operators),
		Adopted:   adopted,
	}, nil
}

// relayOnlyConfig returns conf without listen or advertised addresses: the ceremony runs beside this node's
// charon run with the same peer ID, so it must only connect via relays.
func relayOnlyConfig(conf Config) Config {
	conf.P2P.TCPAddrs = nil
	conf.P2P.UDPAddrs = nil
	conf.P2P.ExternalIP = ""
	conf.P2P.ExternalHost = ""

	return conf
}

// participants returns the participating operators' peers in lock order: all operators without ENRs, else the
// listed ones, which must be distinct lock operators, include this node and number at least the threshold.
func participants(lock cluster.Lock, enrs []string, self peer.ID) ([]p2p.Peer, error) {
	peers, err := lock.Peers()
	if err != nil {
		return nil, err
	}

	if len(enrs) == 0 {
		return peers, nil
	}

	if len(enrs) < lock.Threshold {
		return nil, errors.New("participating operators below the threshold", z.Int("participating", len(enrs)), z.Int("threshold", lock.Threshold))
	}

	var resp []p2p.Peer

	for i, operator := range lock.Operators {
		n := slices.Index(enrs, operator.ENR)
		if n < 0 {
			continue
		}

		if slices.Contains(enrs[n+1:], operator.ENR) {
			return nil, errors.New("participating operator ENR duplicated", z.Int("operator", i))
		}

		resp = append(resp, peers[i])
	}

	if len(resp) != len(enrs) {
		return nil, errors.New("participating operator ENR not in the cluster lock")
	}

	if !slices.ContainsFunc(resp, func(p p2p.Peer) bool { return p.ID == self }) {
		return nil, errors.New("this node is not among the participating operators")
	}

	return resp, nil
}

// loadEditBase returns this node's proposer config document, or the initial one without a file, and whether a
// file exists, whose archive of its revision must be free.
func loadEditBase(ctx context.Context, lock cluster.Lock, nodeIdx cluster.NodeIdx, path, overridesFile string) (proposerconfig.Document, bool, error) {
	doc, onDisk, err := loadProposerConfigDocument(ctx, lock, nodeIdx, path, overridesFile, "No proposer config file, editing one derived from the lock and overrides")
	if err != nil {
		return proposerconfig.Document{}, false, err
	}

	if onDisk {
		err = proposerconfig.CheckArchive(path, doc.Revision)
		if err != nil {
			return proposerconfig.Document{}, false, err
		}
	}

	return doc, onDisk, nil
}

// editProposal returns the next revision of base with the delta applied.
func editProposal(lock cluster.Lock, base proposerconfig.Document, delta proposerconfig.Delta) (proposerconfig.Document, error) {
	cfg, err := proposerconfig.Apply(lock, base.Config, delta)
	if err != nil {
		return proposerconfig.Document{}, errors.Wrap(err, "apply proposer config change")
	}

	return proposerconfig.Document{
		Version:  proposerconfig.Version,
		LockHash: lock.LockHash,
		Revision: base.Revision + 1,
		Config:   cfg,
	}, nil
}

// logEditDiff logs the changed fields of the proposal, so the operator sees what they sign.
func logEditDiff(ctx context.Context, lock cluster.Lock, base, proposal proposerconfig.Document) {
	log.Info(ctx, fmt.Sprintf("Proposing proposer config revision %d, changes from revision %d:", proposal.Revision, base.Revision))

	for _, line := range proposerconfig.Diff(lock, base.Config, proposal.Config) {
		log.Info(ctx, "  "+line)
	}
}

// docDiffLines returns the differences from a to b as "field: old -> new" lines.
func docDiffLines(lock cluster.Lock, a, b proposerconfig.Document) []string {
	var lines []string

	add := func(field, oldVal, newVal string) {
		if oldVal != newVal {
			lines = append(lines, field+": "+oldVal+" -> "+newVal)
		}
	}

	add("version", a.Version, b.Version)
	add("lock_hash", hex.EncodeToString(a.LockHash), hex.EncodeToString(b.LockHash))
	add("revision", strconv.FormatUint(a.Revision, 10), strconv.FormatUint(b.Revision, 10))

	return append(lines, proposerconfig.Diff(lock, a.Config, b.Config)...)
}

// probeRelays fails if any relay holds a reservation for this node's peer ID, i.e. serves its charon run.
func probeRelays(ctx context.Context, relayAddrs []string, lock cluster.Lock, self peer.ID) error {
	if len(relayAddrs) == 0 {
		return nil
	}

	// Cancelling stops the relay resolution.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	relays, err := p2p.NewRelays(ctx, relayAddrs, hex.EncodeToString(lock.LockHash), lock.UUID)
	if err != nil {
		return err
	}

	for i, relay := range relays {
		addr := relayAddrs[i]

		relayPeer, err := awaitRelayPeer(ctx, relay)
		if err != nil {
			return errors.Wrap(err, "resolve relay", z.Str("relay", addr))
		}

		probeCtx, cancelProbe := context.WithTimeout(ctx, relayProbeTimeout)
		reserved, err := p2p.RelayHasReservation(probeCtx, relayPeer.AddrInfo(), self)

		cancelProbe()

		if err != nil {
			return errors.Wrap(err, "relay could not be confirmed free of this node's charon run", z.Str("relay", addr))
		}

		if reserved {
			return errors.New("relay " + addr + " already serves this node's charon run, pass different --p2p-relays (or CHARON_P2P_RELAYS)")
		}
	}

	log.Info(ctx, "Relays confirmed free of this node's charon run", z.Int("relays", len(relays)))

	return nil
}

// awaitRelayPeer returns the relay's peer once resolved.
func awaitRelayPeer(ctx context.Context, relay *p2p.MutablePeer) (p2p.Peer, error) {
	ctx, cancel := context.WithTimeout(ctx, relayResolveTimeout)
	defer cancel()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		relayPeer, ok := relay.Peer()
		if ok {
			return relayPeer, nil
		}

		select {
		case <-ctx.Done():
			return p2p.Peer{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

// participantNames returns the sorted peer ID strings.
func participantNames(peerIDs []peer.ID) []string {
	var resp []string
	for _, pID := range peerIDs {
		resp = append(resp, pID.String())
	}

	slices.Sort(resp)

	return resp
}

// resolveEditBase applies the round 1 rules to the peers' current documents, keyed by operator index. Every
// peer must run with the same participants. Peer documents failing verification are ignored. Two valid
// signed documents at the same revision with different hashes are a fatal inconsistency. The highest valid
// revision above this node's own is adopted as the base, from the lowest operator holding it.
func resolveEditBase(ctx context.Context, lock cluster.Lock, myOperator int, localDoc proposerconfig.Document, participants []string,
	msgs map[int]*dkgpb.MsgProposerConfigEdit,
) (base proposerconfig.Document, adoptedFrom int, adopted bool, err error) {
	type operatorDoc struct {
		operator int
		doc      proposerconfig.Document
		hash     [32]byte
	}

	localHash, err := localDoc.Hash()
	if err != nil {
		return proposerconfig.Document{}, 0, false, err
	}

	docs := []operatorDoc{{operator: myOperator, doc: localDoc, hash: localHash}}

	for _, operator := range slices.Sorted(maps.Keys(msgs)) {
		msg := msgs[operator]

		if !slices.Equal(msg.GetParticipants(), participants) {
			return proposerconfig.Document{}, 0, false, errors.New("operator "+strconv.Itoa(operator)+" froze a different participant set",
				z.Str("participants", strings.Join(participants, ",")), z.Str("peer_participants", strings.Join(msg.GetParticipants(), ",")))
		}

		doc, err := proposerconfig.Unmarshal(msg.GetCurrentRevision())
		if err == nil {
			err = proposerconfig.Verify(doc, lock)
		}

		if err != nil {
			log.Warn(ctx, "Ignoring operator's invalid proposer config", err, z.Int("operator", operator))
			continue
		}

		hash, err := doc.Hash()
		if err != nil {
			return proposerconfig.Document{}, 0, false, err
		}

		docs = append(docs, operatorDoc{operator: operator, doc: doc, hash: hash})
	}

	slices.SortFunc(docs, func(a, b operatorDoc) int { return a.operator - b.operator })

	for i, a := range docs {
		for _, b := range docs[i+1:] {
			if a.doc.Revision == 0 || a.doc.Revision != b.doc.Revision || a.hash == b.hash {
				continue
			}

			return proposerconfig.Document{}, 0, false, errors.New("operator " + strconv.Itoa(a.operator) + " and operator " + strconv.Itoa(b.operator) +
				" have a different signed revision " + strconv.FormatUint(a.doc.Revision, 10) + ":\n" +
				strings.Join(docDiffLines(lock, a.doc, b.doc), "\n"))
		}
	}

	latestDoc := operatorDoc{operator: myOperator, doc: localDoc}

	for _, d := range docs {
		if d.doc.Revision > latestDoc.doc.Revision {
			latestDoc = d
		}
	}

	if latestDoc.operator == myOperator {
		return localDoc, 0, false, nil
	}

	return latestDoc.doc, latestDoc.operator, true, nil
}

// checkEditProposals returns the peers' signatures of the proposal, keyed by operator index in the messages,
// failing on the first differing proposal or invalid signature in operator order.
func checkEditProposals(lock cluster.Lock, proposal proposerconfig.Document, msgs map[int]*dkgpb.MsgProposerConfigEdit) ([]proposerconfig.Signature, error) {
	hash, err := proposal.Hash()
	if err != nil {
		return nil, err
	}

	var sigs []proposerconfig.Signature

	for _, operator := range slices.Sorted(maps.Keys(msgs)) {
		msg := msgs[operator]

		doc, err := proposerconfig.Unmarshal(msg.GetProposal())
		if err != nil {
			return nil, errors.Wrap(err, "decode operator proposal", z.Int("operator", operator))
		}

		peerHash, err := doc.Hash()
		if err != nil {
			return nil, err
		}

		if peerHash != hash {
			return nil, errors.New("operator " + strconv.Itoa(operator) + " proposed a different document:\n" +
				strings.Join(docDiffLines(lock, proposal, doc), "\n"))
		}

		err = proposerconfig.VerifySignature(proposal, lock, operator, msg.GetSignature())
		if err != nil {
			return nil, errors.Wrap(err, "verify operator signature", z.Int("operator", operator))
		}

		sigs = append(sigs, proposerconfig.Signature{Operator: operator, Signature: msg.GetSignature()})
	}

	return sigs, nil
}

// writeEditResult verifies the proposal with the signatures, archives the file loaded at start (disk, nil if
// there was none) and writes the new revision. It writes nothing if the file on disk is no longer disk.
func writeEditResult(lock cluster.Lock, nodeIdx cluster.NodeIdx, path string, proposal proposerconfig.Document,
	sigs []proposerconfig.Signature, disk *proposerconfig.Document,
) (proposerconfig.Document, error) {
	doc := proposal
	doc.Signatures = slices.SortedFunc(slices.Values(sigs), func(a, b proposerconfig.Signature) int { return a.Operator - b.Operator })

	err := proposerconfig.Verify(doc, lock)
	if err != nil {
		return proposerconfig.Document{}, errors.Wrap(err, "verify signed proposer config")
	}

	err = checkFileUnchanged(lock, nodeIdx, path, disk)
	if err != nil {
		return proposerconfig.Document{}, err
	}

	if disk != nil {
		err = proposerconfig.Archive(path, disk.Revision)
		if err != nil {
			return proposerconfig.Document{}, err
		}
	}

	err = proposerconfig.Write(path, doc, lock, nodeIdx)
	if err != nil {
		return proposerconfig.Document{}, err
	}

	return doc, nil
}

// checkFileUnchanged returns an error if the file at path is no longer disk, the document loaded at start (nil if
// absent): a file replaced, created or removed during the ceremony would be archived under the wrong revision or lost.
func checkFileUnchanged(lock cluster.Lock, nodeIdx cluster.NodeIdx, path string, disk *proposerconfig.Document) error {
	changed := errors.New("proposer config file changed during the ceremony, nothing written; rerun the edit", z.Str("path", path))

	cur, err := proposerconfig.Load(path, lock, nodeIdx)
	if errors.Is(err, proposerconfig.ErrNotFound) {
		if disk != nil {
			return changed
		}

		return nil
	} else if err != nil {
		return errors.Wrap(err, "reload proposer config before writing")
	}

	if disk == nil {
		return changed
	}

	curHash, err := cur.Hash()
	if err != nil {
		return err
	}

	diskHash, err := disk.Hash()
	if err != nil {
		return err
	}

	if curHash != diskHash {
		return changed
	}

	return nil
}

// editExchange serves this node's round messages to the participants and fetches theirs.
type editExchange struct {
	p2pNode   host.Host
	operators map[peer.ID]int

	mu     sync.Mutex
	others []peer.ID
	msgs   map[uint32]*dkgpb.MsgProposerConfigEdit
}

// newEditExchange returns an exchange with its handler registered on the node.
func newEditExchange(p2pNode host.Host, peers []p2p.Peer) *editExchange {
	operators := make(map[peer.ID]int)
	for _, p := range peers {
		operators[p.ID] = p.Index
	}

	ex := &editExchange{
		p2pNode:   p2pNode,
		operators: operators,
		msgs:      make(map[uint32]*dkgpb.MsgProposerConfigEdit),
	}

	p2p.RegisterHandler("edit", p2pNode, editProtocolID,
		func() proto.Message { return new(dkgpb.MsgProposerConfigEdit) },
		ex.handle, p2p.WithReadLimit(maxEditRequestSize))

	return ex
}

// start sets the participants, excluding this node.
func (e *editExchange) start(others []peer.ID) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.others = others
}

// prepare stores this node's message for its round.
func (e *editExchange) prepare(msg *dkgpb.MsgProposerConfigEdit) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.msgs[msg.GetRound()] = msg
}

// handle answers a participant's request with this node's message for the requested round.
func (e *editExchange) handle(_ context.Context, pID peer.ID, req proto.Message) (proto.Message, bool, error) {
	msg, ok := req.(*dkgpb.MsgProposerConfigEdit)
	if !ok {
		return nil, false, errors.New("invalid proposer config edit request")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if !slices.Contains(e.others, pID) {
		return nil, false, errors.New("proposer config edit request from a non-participant")
	}

	resp, ok := e.msgs[msg.GetRound()]
	if !ok {
		return nil, false, errors.New("proposer config edit round not prepared", z.Uint("round", uint(msg.GetRound())))
	}

	return resp, true, nil
}

// exchange waits for all participants to prepare the round, then fetches their messages keyed by operator index.
func (e *editExchange) exchange(ctx context.Context, stepSync func(context.Context) error, round uint32) (map[int]*dkgpb.MsgProposerConfigEdit, error) {
	err := stepSync(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "sync proposer config edit round", z.Uint("round", uint(round)))
	}

	e.mu.Lock()
	others := e.others
	e.mu.Unlock()

	type result struct {
		operator int
		msg      *dkgpb.MsgProposerConfigEdit
		err      error
	}

	results := make(chan result, len(others))

	for _, pID := range others {
		go func() {
			resp := new(dkgpb.MsgProposerConfigEdit)

			err := p2p.SendReceive(ctx, e.p2pNode, pID, &dkgpb.MsgProposerConfigEdit{Round: round}, resp, editProtocolID,
				p2p.WithReadLimit(maxEditMsgSize), p2p.WithRetries(sendRetries), p2p.WithSendTimeout(sendTimeout))
			results <- result{operator: e.operators[pID], msg: resp, err: err}
		}()
	}

	msgs := make(map[int]*dkgpb.MsgProposerConfigEdit)

	var errs []error

	for range others {
		res := <-results
		if res.err != nil {
			errs = append(errs, errors.Wrap(res.err, "fetch proposer config edit message", z.Int("operator", res.operator)))
			continue
		}

		if res.msg.GetRound() != round {
			errs = append(errs, errors.New("unexpected proposer config edit round", z.Int("operator", res.operator), z.Uint("round", uint(res.msg.GetRound()))))
			continue
		}

		msgs[res.operator] = res.msg
	}

	if len(errs) == 0 {
		return msgs, nil
	}

	// Every failure is logged, the first is returned.
	for _, err := range errs[1:] {
		log.Warn(ctx, "Proposer config edit message not fetched", err)
	}

	return nil, errs[0]
}
