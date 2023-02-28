// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package consensus

import (
	"encoding/hex"
	"math/rand"
	"testing"

	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/core"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/core/qbft"
	"github.com/obolnetwork/charon/testutil"
)

//go:generate go test . -update -clean

func TestHashProto(t *testing.T) {
	rand.Seed(0)
	set := testutil.RandomUnsignedDataSet(t)
	testutil.RequireGoldenJSON(t, set)

	setPB, err := core.UnsignedDataSetToProto(set)
	require.NoError(t, err)
	hash, err := hashProto(setPB)
	require.NoError(t, err)

	require.Equal(t,
		"09d28bb0414151be4330871ca94a473a69938c8c3ee934b18c85b9e9c7118858",
		hex.EncodeToString(hash[:]),
	)
}

//go:generate go test . -update

func TestSigning(t *testing.T) {
	privkey, err := k1.GeneratePrivateKey()
	require.NoError(t, err)

	msg := randomMsg(t)

	signed, err := signMsg(msg, privkey)
	require.NoError(t, err)

	ok, err := verifyMsgSig(signed, privkey.PubKey())
	require.NoError(t, err)
	require.True(t, ok)

	privkey2, err := k1.GeneratePrivateKey()
	require.NoError(t, err)
	ok, err = verifyMsgSig(signed, privkey2.PubKey())
	require.NoError(t, err)
	require.False(t, ok)
}

func TestBackwardsCompatibility(t *testing.T) {
	// Marshalled proto and private key and hash of v0.10.0 test data (pre "any" fields).
	const (
		prevKey   = "abea1c141809315ab6ce254f1d57f31585eefa747da5a93a15c04d86823d07c8"
		prevProto = "08abc4d194c3f6a1e120121508fcbaf3a3efcab6e13a10e0ab87f7fbffffffff011891a0ceb6e8a1f1c05a2098a1d0bdecd0d58a522ac5060ac2060a62307838313533343463323736376533363637313232666134396231653365623566353432393436626432323831383563613530636561323636656361376432353463353434646535636435613564323865376639343435623862316463646236616112db057b226174746573746174696f6e5f64617461223a7b22736c6f74223a223137353138313531393130383539373634343138222c22696e646578223a223133333835393738313132313133353433323131222c22626561636f6e5f626c6f636b5f726f6f74223a22307864363465633062613332643632356662306434306631303637646630626130336461613839666164353163643233613665323631336331636434636366666237222c22736f75726365223a7b2265706f6368223a2233343538393238303531343237303637393033222c22726f6f74223a22307833643837633863346264343561646537373937353732386463363136346134313639626630393231633231376439336430363566323539316463333966633534227d2c22746172676574223a7b2265706f6368223a2232303733323031363734383031353836393738222c22726f6f74223a22307833663562333539356634633965666532303363373836303235306533643234633065366462366162303535326436663538346335316636363230326131303565227d7d2c226174746573746174696f6e5f64757479223a7b227075626b6579223a223078613430616634353066366332353437623737343763643161663864333466353662303135613034356136313237366166613163643230343230636332303437353365633834636336313932323437653337626565336439643735303936303037222c22736c6f74223a2237383038303232343334313738313734343530222c2276616c696461746f725f696e646578223a2235363935363833393839383938383832333731222c22636f6d6d69747465655f696e646578223a2231323739383533383835313231303538333238222c22636f6d6d69747465655f6c656e677468223a22323536222c22636f6d6d6974746565735f61745f736c6f74223a22323536222c2276616c696461746f725f636f6d6d69747465655f696e646578223a223738227d7d309ff58092bfd6da9e2a3ac9060ac6060a62307861316633313132343034636635336362396431383062643235333666663639326431323130653135373436313064373030666235323534306531633566633931353439343934303063353332326333316366303330643235313032333938663412df057b226174746573746174696f6e5f64617461223a7b22736c6f74223a223130323032303930313639313634313534313033222c22696e646578223a223134343434383730383234363937353735383637222c22626561636f6e5f626c6f636b5f726f6f74223a22307832363566663231633665323832313466656662306365623862303138333937363134303861656239343961323133643239393338383465396362366365383335222c22736f75726365223a7b2265706f6368223a2231353437353536383039303739393931333833222c22726f6f74223a22307838336535323631383162613638643661666537383635323164306233383938326166303766626136353866623464313430666535313939353939306336663539227d2c22746172676574223a7b2265706f6368223a223133353631313431353035363338383634353730222c22726f6f74223a22307862626261376661663138313166633533663466643365646565316636313365633634313931336438656636666561356165623037343433393464373533363437227d7d2c226174746573746174696f6e5f64757479223a7b227075626b6579223a223078613965313866343738373765383034303430353537343334353563313964323132366138376433623836376537656635303633633163623530333934306330376661336665356561366538306331363264643839353164333936646362303435222c22736c6f74223a223133333339363330373334373036333233353936222c2276616c696461746f725f696e646578223a2231393635373831373036303737313638373035222c22636f6d6d69747465655f696e646578223a223138313838323336373834323134303739393633222c22636f6d6d69747465655f6c656e677468223a22323536222c22636f6d6d6974746565735f61745f736c6f74223a22323536222c2276616c696461746f725f636f6d6d69747465655f696e646578223a22323337227d7d42417d121915a6ada991d4af3139c2475d68c25ad9a440a8d8105dddd1d8b14d48a911dc1dd4c3cbb56c11a0a07a9b55eb6353ebb096314ef679400033f50a20220300"
		prevHash  = "9d050b2bec1435314ec7588a5b4cb903332fae4c9ecc930d8acc13a7e65a59d9"
	)

	prevKeyBytes, err := hex.DecodeString(prevKey)
	require.NoError(t, err)
	key := k1.PrivKeyFromBytes(prevKeyBytes)

	t.Run("previous wire, latest logic", func(t *testing.T) {
		msg := new(pbv1.QBFTMsg)
		prevProtoBytes, err := hex.DecodeString(prevProto)
		require.NoError(t, err)
		err = proto.Unmarshal(prevProtoBytes, msg)
		require.NoError(t, err)

		ok, err := verifyMsgSig(msg, key.PubKey())
		testutil.RequireNoError(t, err)
		require.True(t, ok)

		msg2, err := signMsg(msg, key)
		require.NoError(t, err)
		require.Equal(t, msg.Signature, msg2.Signature)

		expectHash, err := hex.DecodeString(prevHash)
		require.NoError(t, err)

		msg.Signature = nil
		hash, err := hashProto(msg)
		require.NoError(t, err)
		require.Equal(t, expectHash, hash[:])
	})

	t.Run("latest wire, previous logic", func(t *testing.T) {
		msg, err := signMsg(randomMsg(t), key)
		require.NoError(t, err)

		wireBytes, err := proto.Marshal(msg)
		require.NoError(t, err)

		msg.Signature = nil
		hashLatest, err := hashProto(msg)
		require.NoError(t, err)

		msgLegacy := new(pbv1.QBFTMsgLegacy)
		err = proto.Unmarshal(wireBytes, msgLegacy)
		require.NoError(t, err)

		sigLegacy := msgLegacy.Signature
		msgLegacy.Signature = nil
		hashLegacy, err := hashProto(msgLegacy)
		require.NoError(t, err)
		require.Equal(t, hashLegacy, hashLatest)

		recovered, err := k1util.Recover(hashLegacy[:], sigLegacy)
		require.NoError(t, err)
		require.True(t, key.PubKey().IsEqual(recovered))
	})
}

// randomMsg returns a random qbft message.
func randomMsg(t *testing.T) *pbv1.QBFTMsg {
	t.Helper()

	vLegacy, err := core.UnsignedDataSetToProto(testutil.RandomUnsignedDataSet(t))
	require.NoError(t, err)
	pvLegacy, err := core.UnsignedDataSetToProto(testutil.RandomUnsignedDataSet(t))
	require.NoError(t, err)

	v, err := anypb.New(vLegacy)
	require.NoError(t, err)
	pv, err := anypb.New(pvLegacy)
	require.NoError(t, err)

	return &pbv1.QBFTMsg{
		Type:          rand.Int63(),
		Duty:          core.DutyToProto(core.Duty{Type: core.DutyType(rand.Int()), Slot: rand.Int63()}),
		PeerIdx:       rand.Int63(),
		Round:         rand.Int63(),
		Value:         v,
		PreparedRound: rand.Int63(),
		PreparedValue: pv,
		Signature:     nil,
	}
}

// TestLegacyMsgHashAndSig ensures that the QBFTMsgLegacy produces the same hash and signature as
// previously. The test data was generated in v0.10.1.
func TestLegacyMsgHashAndSig(t *testing.T) {
	v, err := core.UnsignedDataSetToProto(core.UnsignedDataSet{
		"0x1234": core.AttestationData{Data: eth2p0.AttestationData{
			Slot:  99,
			Index: 98,
		}},
	})
	require.NoError(t, err)

	pv, err := core.UnsignedDataSetToProto(core.UnsignedDataSet{
		"0x4567": core.AttestationData{Data: eth2p0.AttestationData{
			Slot:  98,
			Index: 97,
		}},
	})
	require.NoError(t, err)

	msg := &pbv1.QBFTMsgLegacy{
		Type:          int64(qbft.MsgCommit),
		Duty:          core.DutyToProto(core.NewAttesterDuty(99)),
		PeerIdx:       98,
		Round:         97,
		Value:         v,
		PreparedRound: 96,
		PreparedValue: pv,
	}

	hash, err := hashProto(msg)
	require.NoError(t, err)

	privkey := testutil.GenerateInsecureK1Key(t, 1)

	sig, err := k1util.Sign(privkey, hash[:])
	require.NoError(t, err)

	require.Equal(t,
		"ae61d6f1352ba4a88a1a40642218b0841b9725bd1a0c5148b3895adcd5151bc7",
		hex.EncodeToString(hash[:]),
	)
	require.Equal(t,
		"3590cdb8495d733414bd42c9826396936ea582278617a829b51f46c91618088244baf8f3d9e2ca944c214106b1f5115d9d9ebbec53818fa30d2ddbbd06eb640e00",
		hex.EncodeToString(sig),
	)

	legacyWire, err := proto.Marshal(msg)
	require.NoError(t, err)

	latestMsg := new(pbv1.QBFTMsg)
	err = proto.Unmarshal(legacyWire, latestMsg)
	require.NoError(t, err)

	latestMsg.Signature = nil
	hash2, err := hashProto(latestMsg)
	require.NoError(t, err)
	require.Equal(t, hash, hash2)
}
