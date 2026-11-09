// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package proposerconfig

import (
	"bytes"
	"cmp"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
)

// ErrNotFound is returned by Load if the proposer config file does not exist.
var ErrNotFound = errors.Wrap(os.ErrNotExist, "proposer config file not found")

// documentJSON is the JSON form of a Document, field order is the file's field order.
type documentJSON struct {
	Version        string              `json:"version"`
	LockHash       string              `json:"lock_hash"`
	Revision       uint64              `json:"revision"`
	RevisionHash   string              `json:"revision_hash"`
	ProposerConfig map[string]Settings `json:"proposer_config"`
	DefaultConfig  Settings            `json:"default_config"`
	Signatures     []signatureJSON     `json:"signatures"`
}

type signatureJSON struct {
	Operator  int    `json:"operator"`
	Signature string `json:"signature"`
}

// Marshal returns the JSON form of the document keyed by DV pubkeys, as exchanged between operators.
// The revision hash is recomputed from the config.
func Marshal(doc Document) ([]byte, error) {
	hash, err := doc.Hash()
	if err != nil {
		return nil, err
	}

	return marshal(doc, hash)
}

// Unmarshal parses the JSON form, keeping its keys as they are and its revision hash as StoredHash.
func Unmarshal(b []byte) (Document, error) {
	var w documentJSON
	if err := json.Unmarshal(b, &w); err != nil {
		return Document{}, errors.Wrap(err, "unmarshal proposer config")
	}

	lockHash, err := decodeHex(w.LockHash)
	if err != nil {
		return Document{}, errors.Wrap(err, "decode lock hash")
	}

	storedHash, err := decodeHex(w.RevisionHash)
	if err != nil {
		return Document{}, errors.Wrap(err, "decode revision hash")
	}

	var sigs []Signature

	for _, s := range w.Signatures {
		sig, err := decodeHex(s.Signature)
		if err != nil {
			return Document{}, errors.Wrap(err, "decode signature", z.Int("operator", s.Operator))
		}

		sigs = append(sigs, Signature{Operator: s.Operator, Signature: sig})
	}

	return Document{
		Version:  w.Version,
		LockHash: lockHash,
		Revision: w.Revision,
		Config: Config{
			DefaultConfig:  w.DefaultConfig,
			ProposerConfig: w.ProposerConfig,
		},
		Signatures: sigs,
		StoredHash: storedHash,
	}, nil
}

// marshal returns the JSON form of the document with the given revision hash, keeping its keys as they are.
func marshal(doc Document, hash [32]byte) ([]byte, error) {
	proposerConfig := make(map[string]Settings, len(doc.Config.ProposerConfig))
	for k, v := range doc.Config.ProposerConfig {
		proposerConfig[k] = canonicalSettings(v)
	}

	sigs := make([]signatureJSON, 0, len(doc.Signatures))
	for _, s := range doc.Signatures {
		sigs = append(sigs, signatureJSON{Operator: s.Operator, Signature: "0x" + hex.EncodeToString(s.Signature)})
	}

	slices.SortStableFunc(sigs, func(a, b signatureJSON) int { return cmp.Compare(a.Operator, b.Operator) })

	b, err := json.MarshalIndent(documentJSON{
		Version:        doc.Version,
		LockHash:       "0x" + hex.EncodeToString(doc.LockHash),
		Revision:       doc.Revision,
		RevisionHash:   "0x" + hex.EncodeToString(hash[:]),
		ProposerConfig: proposerConfig,
		DefaultConfig:  canonicalSettings(doc.Config.DefaultConfig),
		Signatures:     sigs,
	}, "", "  ")
	if err != nil {
		return nil, errors.Wrap(err, "marshal proposer config")
	}

	return append(b, '\n'), nil
}

func decodeHex(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return nil, errors.Wrap(err, "decode hex")
	}

	return b, nil
}

// pubshareMaps returns DV pubkey to this node's pubshare (and the reverse), both lowercase 0x hex.
func pubshareMaps(lock cluster.Lock, nodeIdx cluster.NodeIdx) (toShare, toPubkey map[string]string, err error) {
	toShare = make(map[string]string, len(lock.Validators))
	toPubkey = make(map[string]string, len(lock.Validators))

	for i, val := range lock.Validators {
		share, err := val.PublicShare(nodeIdx.PeerIdx)
		if err != nil {
			return nil, nil, errors.Wrap(err, "pubshare", z.Int("validator", i))
		}

		pubkey := pubkeyHex(val.PubKey)
		pubshare := fmt.Sprintf("%#x", share)

		toShare[pubkey] = pubshare
		toPubkey[pubshare] = pubkey
	}

	return toShare, toPubkey, nil
}

// rekey returns the proposer_config with each key replaced by keys[key], erroring on a key not in keys.
// keyName names the input keys in the error.
func rekey(in map[string]Settings, keys map[string]string, keyName string) (map[string]Settings, error) {
	out := make(map[string]Settings, len(in))

	for k, v := range in {
		renamed, ok := keys[strings.ToLower(k)]
		if !ok {
			return nil, errors.New("unknown "+keyName, z.Str(keyName, k))
		}

		out[renamed] = v
	}

	return out, nil
}

// Load reads the proposer config file, keyed by this node's pubshares, and returns it keyed by DV pubkeys.
// A file of another lock returns ErrLockHashMismatch.
func Load(path string, lock cluster.Lock, nodeIdx cluster.NodeIdx) (Document, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Document{}, errors.Wrap(ErrNotFound, "load proposer config", z.Str("path", path))
	} else if err != nil {
		return Document{}, errors.Wrap(err, "read proposer config", z.Str("path", path))
	}

	_, toPubkey, err := pubshareMaps(lock, nodeIdx)
	if err != nil {
		return Document{}, err
	}

	doc, err := Unmarshal(b)
	if err != nil {
		return Document{}, errors.Wrap(err, "load proposer config", z.Str("path", path))
	}

	// Checked before re-keying, another cluster's pubshares would otherwise fail as unknown.
	if !bytes.Equal(doc.LockHash, lock.LockHash) {
		return Document{}, errors.Wrap(ErrLockHashMismatch, "proposer config file lock hash differs from lock", z.Str("path", path))
	}

	// The file is keyed by this node's pubshares, the document by DV pubkeys.
	doc.Config.ProposerConfig, err = rekey(doc.Config.ProposerConfig, toPubkey, "pubshare")
	if err != nil {
		return Document{}, err
	}

	return doc, nil
}

// render returns the file contents of the document, keyed by this node's pubshares instead of DV pubkeys.
func render(doc Document, lock cluster.Lock, nodeIdx cluster.NodeIdx) ([]byte, error) {
	// Hashed before re-keying: the revision hash covers the DV pubkeys, the same on every node.
	hash, err := doc.Hash()
	if err != nil {
		return nil, err
	}

	toShare, _, err := pubshareMaps(lock, nodeIdx)
	if err != nil {
		return nil, err
	}

	doc.Config.ProposerConfig, err = rekey(doc.Config.ProposerConfig, toShare, "pubkey")
	if err != nil {
		return nil, err
	}

	return marshal(doc, hash)
}

// Write atomically writes the document, keyed by DV pubkeys, to path keyed by this node's pubshares, creating
// the directory.
func Write(path string, doc Document, lock cluster.Lock, nodeIdx cluster.NodeIdx) error {
	b, err := render(doc, lock, nodeIdx)
	if err != nil {
		return err
	}

	return writeAtomic(path, b)
}

// writeAtomic writes data to a temp file in the same directory and renames it to path, mode 0644.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return errors.Wrap(err, "create directory", z.Str("path", dir))
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return errors.Wrap(err, "create temp file", z.Str("path", dir))
	}

	cleanup := func(err error, msg string) error {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())

		return errors.Wrap(err, msg, z.Str("path", path))
	}

	if _, err := tmp.Write(data); err != nil {
		return cleanup(err, "write temp file")
	}

	if err := tmp.Chmod(0o644); err != nil {
		return cleanup(err, "chmod temp file")
	}

	if err := tmp.Sync(); err != nil {
		return cleanup(err, "sync temp file")
	}

	if err := tmp.Close(); err != nil {
		return cleanup(err, "close temp file")
	}

	if err := os.Rename(tmp.Name(), path); err != nil {
		return cleanup(err, "rename temp file")
	}

	return nil
}

// ArchivePath returns the archive path of a revision, next to the file at path.
func ArchivePath(path string, revision uint64) string {
	return filepath.Join(filepath.Dir(path), fmt.Sprintf("proposer-config-revision-%d.json", revision))
}

// CheckArchive returns an error if the revision's archive exists and differs from the file at path.
func CheckArchive(path string, revision uint64) error {
	_, err := checkArchive(path, revision)
	return err
}

// checkArchive returns the current file's contents and whether the archive already holds them.
func checkArchive(path string, revision uint64) (current []byte, err error) {
	current, err = os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrap(err, "read proposer config", z.Str("path", path))
	}

	archive := ArchivePath(path, revision)

	existing, err := os.ReadFile(archive)
	if errors.Is(err, os.ErrNotExist) {
		return current, nil
	} else if err != nil {
		return nil, errors.Wrap(err, "read archive", z.Str("path", archive))
	}

	if !bytes.Equal(existing, current) {
		return nil, errors.New("proposer config archive exists and differs, move it away first", z.Str("path", archive))
	}

	return current, nil
}

// Archive copies the file at path byte for byte to the revision's archive; it is a no-op if an identical one exists.
func Archive(path string, revision uint64) error {
	current, err := checkArchive(path, revision)
	if err != nil {
		return err
	}

	return writeAtomic(ArchivePath(path, revision), current)
}
