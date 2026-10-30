// Command zz_spec_vectors emits golden hashProto values for the
// distributed-validator-specs test vectors. Temporary generator, not part of charon.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	ssz "github.com/ferranbt/fastssz"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
)

// hashProto is copied verbatim from core/consensus/qbft/msg.go and core/priority/prioritiser.go.
func hashProto(msg proto.Message) ([32]byte, error) {
	hh := ssz.DefaultHasherPool.Get()
	defer ssz.DefaultHasherPool.Put(hh)

	index := hh.Index()

	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		return [32]byte{}, err
	}

	hh.PutBytes(b)
	hh.Merkleize(index)

	return hh.HashRoot()
}

func mustHash(msg proto.Message) (string, string) {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		panic(err)
	}

	h, err := hashProto(msg)
	if err != nil {
		panic(err)
	}

	return hex.EncodeToString(b), hex.EncodeToString(h[:])
}

type out struct {
	Name     string `json:"name"`
	Encoding string `json:"encoding_hex"`
	Hash     string `json:"hash_hex"`
}

func main() {
	res := map[string][]out{}

	// --- UnsignedDataSet: map<string,bytes> determinism and edge cases.
	sets := []struct {
		name string
		set  map[string][]byte
	}{
		{"empty_set", map[string][]byte{}},
		{"single_entry", map[string][]byte{"0xaabb": {0x01, 0x02, 0x03}}},
		{"empty_value", map[string][]byte{"0xaabb": {}}},
		{"empty_key", map[string][]byte{"": {0x01}}},
		{"short_entry_under_32_bytes", map[string][]byte{"a": []byte("b")}},
		{"three_entries_reverse_insertion", map[string][]byte{
			"0xcccc": {0x03},
			"0xbbbb": {0x02},
			"0xaaaa": {0x01},
		}},
		{"long_value_multi_chunk", map[string][]byte{
			"0xaabb": make([]byte, 100),
		}},
	}
	for _, s := range sets {
		enc, h := mustHash(&pbv1.UnsignedDataSet{Set: s.set})
		res["unsigned_data_set"] = append(res["unsigned_data_set"], out{s.name, enc, h})
	}

	// --- QBFTMsg signing roots: hashProto of the message with Signature cleared.
	// Both hash fields are always 32 bytes, as createMsg passes [32]byte slices;
	// an absent value is all zeros, never an absent field.
	msgs := []struct {
		name string
		msg  *pbv1.QBFTMsg
	}{
		{"minimal_pre_prepare", &pbv1.QBFTMsg{
			Type: 1, Duty: &pbv1.Duty{}, PeerIdx: 0, Round: 1,
			ValueHash: bytes32(0x00), PreparedValueHash: bytes32(0x00),
		}},
		{"attester_pre_prepare", &pbv1.QBFTMsg{
			Type: 1, Duty: &pbv1.Duty{Slot: 1234, Type: 2}, PeerIdx: 3, Round: 1,
			ValueHash: bytes32(0xaa), PreparedValueHash: bytes32(0x00),
		}},
		{"attester_pre_prepare_signed", &pbv1.QBFTMsg{
			Type: 1, Duty: &pbv1.Duty{Slot: 1234, Type: 2}, PeerIdx: 3, Round: 1,
			ValueHash: bytes32(0xaa), PreparedValueHash: bytes32(0x00),
			Signature: bytesN(65, 0xdd),
		}},
		{"round_change_prepared", &pbv1.QBFTMsg{
			Type: 4, Duty: &pbv1.Duty{Slot: 999999, Type: 1}, PeerIdx: 2, Round: 7,
			PreparedRound: 3, PreparedValueHash: bytes32(0xbb), ValueHash: bytes32(0xcc),
		}},
		{"decided", &pbv1.QBFTMsg{
			Type: 5, Duty: &pbv1.Duty{Slot: 64, Type: 3}, PeerIdx: 1, Round: 2,
			ValueHash: bytes32(0xee), PreparedValueHash: bytes32(0x00),
		}},
		{"max_slot", &pbv1.QBFTMsg{
			Type: 2, Duty: &pbv1.Duty{Slot: 18446744073709551615, Type: 13}, PeerIdx: 0, Round: 1,
			ValueHash: bytes32(0x00), PreparedValueHash: bytes32(0x00),
		}},
	}
	for _, m := range msgs {
		clone, ok := proto.Clone(m.msg).(*pbv1.QBFTMsg)
		if !ok {
			panic("clone")
		}
		clone.Signature = nil
		enc, h := mustHash(clone)
		res["qbft_signing_root"] = append(res["qbft_signing_root"], out{m.name, enc, h})
	}

	// --- Any-wrapped structpb string values, as used by priority topics/priorities.
	for _, s := range []string{"versions", "/charon/consensus/qbft/2.0.0", "", "v1"} {
		any, err := anypb.New(structpb.NewStringValue(s))
		if err != nil {
			panic(err)
		}
		enc, h := mustHash(any)
		res["any_string"] = append(res["any_string"], out{s, enc, h})
	}

	// --- Duty on its own.
	for _, d := range []*pbv1.Duty{{}, {Slot: 1, Type: 2}, {Slot: 18446744073709551615, Type: 13}} {
		enc, h := mustHash(d)
		res["duty"] = append(res["duty"], out{fmt.Sprintf("slot%d_type%d", d.GetSlot(), d.GetType()), enc, h})
	}

	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	if err := e.Encode(res); err != nil {
		panic(err)
	}
}

func bytes32(b byte) []byte { return bytesN(32, b) }

func bytesN(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}

	return out
}
