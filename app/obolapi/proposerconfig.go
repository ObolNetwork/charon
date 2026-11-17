// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi

import (
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/pk910/dynamic-ssz/hasher"
	"github.com/pk910/dynamic-ssz/sszutils"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster/proposerconfig"
)

const (
	publishProposerConfigTmpl = "/proposer_config/" + lockHashPath
	fetchProposerConfigTmpl   = "/proposer_config/" + lockHashPath + "/" + shareIndexPath
)

var (
	// ErrProposerConfigConflict is returned when the Obol API refuses a proposer config revision, as it holds a later
	// revision or another document of the same revision.
	ErrProposerConfigConflict = errors.NewSentinel("Obol API holds a later or conflicting proposer config revision")
	// ErrProposerConfigNotFound is returned when the Obol API holds no proposer config of the cluster, or not the
	// revision asked for.
	ErrProposerConfigNotFound = errors.NewSentinel("proposer config not found on Obol API")
)

// ProposerConfigAuthBlob is what an operator signs with its identity key to fetch the cluster's proposer config.
type ProposerConfigAuthBlob struct {
	LockHash   []byte
	ShareIndex uint64
}

func (b ProposerConfigAuthBlob) HashTreeRoot() ([32]byte, error) {
	hh := hasher.DefaultHasherPool.Get()
	defer hasher.DefaultHasherPool.Put(hh)

	if err := b.HashTreeRootWith(hh); err != nil {
		return [32]byte{}, errors.Wrap(err, "hash tree root")
	}

	root, err := hh.HashRoot()
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "hash root")
	}

	return root, nil
}

func (b ProposerConfigAuthBlob) HashTreeRootWith(hh sszutils.HashWalker) error {
	indx := hh.Index()

	hh.PutBytes(b.LockHash)
	hh.PutUint64(b.ShareIndex)

	hh.Merkleize(indx)

	return nil
}

// PublishProposerConfig posts a signed proposer config revision, keyed by DV pubkeys, to the Obol API. Its operator
// signatures authenticate it. It respects the timeout specified in the Client instance.
func (c Client) PublishProposerConfig(ctx context.Context, doc proposerconfig.Document) error {
	b, err := proposerconfig.Marshal(doc)
	if err != nil {
		return err
	}

	u := c.url()
	u.Path = strings.NewReplacer(lockHashPath, "0x"+hex.EncodeToString(doc.LockHash)).Replace(publishProposerConfigTmpl)

	ctx, cancel := context.WithTimeout(ctx, c.reqTimeout)
	defer cancel()

	status, data, err := c.httpPostStatus(ctx, u, b, nil)
	if err != nil {
		return err
	}

	switch {
	case status/100 == 2:
		return nil
	case status == http.StatusNotFound:
		return errors.Wrap(ErrLockNotFound, "publish proposer config", z.Str("body", string(data)))
	case status == http.StatusConflict:
		return errors.Wrap(ErrProposerConfigConflict, "publish proposer config", z.U64("revision", doc.Revision), z.Str("body", string(data)))
	default:
		return errors.New("publish proposer config", z.Int("status", status), z.Str("body", string(data)))
	}
}

// GetProposerConfig returns the cluster's proposer config revision from the Obol API, the latest if revision is 0.
// The request is signed by the operator's identity key, as only the cluster's operators may read it. The document is
// unverified: the caller checks it against the lock. It respects the timeout specified in the Client instance.
func (c Client) GetProposerConfig(ctx context.Context, lockHash []byte, shareIndex, revision uint64, identityKey *k1.PrivateKey) (proposerconfig.Document, error) {
	root, err := ProposerConfigAuthBlob{LockHash: lockHash, ShareIndex: shareIndex}.HashTreeRoot()
	if err != nil {
		return proposerconfig.Document{}, errors.Wrap(err, "proposer config auth root")
	}

	sig, err := k1util.Sign(identityKey, root[:])
	if err != nil {
		return proposerconfig.Document{}, errors.Wrap(err, "k1 sign")
	}

	u := c.url()
	u.Path = strings.NewReplacer(
		lockHashPath, "0x"+hex.EncodeToString(lockHash),
		shareIndexPath, strconv.FormatUint(shareIndex, 10),
	).Replace(fetchProposerConfigTmpl)

	if revision > 0 {
		u.RawQuery = url.Values{"revision": {strconv.FormatUint(revision, 10)}}.Encode()
	}

	ctx, cancel := context.WithTimeout(ctx, c.reqTimeout)
	defer cancel()

	body, err := c.httpGet(ctx, u, map[string]string{"Authorization": bearerString(sig)})
	if errors.Is(err, ErrNoValue) {
		return proposerconfig.Document{}, errors.Wrap(ErrProposerConfigNotFound, "fetch proposer config", z.U64("revision", revision))
	} else if err != nil {
		return proposerconfig.Document{}, errors.Wrap(err, "fetch proposer config")
	}
	defer body.Close()

	b, err := io.ReadAll(body)
	if err != nil {
		return proposerconfig.Document{}, errors.Wrap(err, "read proposer config response")
	}

	return proposerconfig.Unmarshal(b)
}
