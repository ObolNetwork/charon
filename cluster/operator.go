// Copyright © 2022 Obol Labs Inc.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.

package cluster

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/p2p/enode"
	ssz "github.com/ferranbt/fastssz"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/p2p"
)

// Operator identifies a charon node and its operator.
type Operator struct {
	// Address is the Ethereum address identifying the operator.
	Address string `json:"address"`

	// ENR identifies the charon node.
	ENR string `json:"enr"`

	// Nonce is incremented each time the ENR is signed.
	Nonce int `json:"nonce"`

	// ENRSignature is a EIP712 signature of the ENR by the Address, authorising the charon node to act on behalf of the operator in the cluster.
	ENRSignature []byte `json:"enr_signature"`
}

// VerifySignature returns an error if the ENR signature doesn't match the address and enr fields.
func (o Operator) VerifySignature() error {
	digest, err := digestEIP712(o.Address, []byte(o.ENR), o.Nonce)
	if err != nil {
		return err
	}

	if ok, err := verifySig(o.Address, digest[:], o.ENRSignature); err != nil {
		return err
	} else if !ok {
		return errors.New("invalid operator enr signature")
	}

	return nil
}

// getName returns a deterministic name for operator based on its ENR.
func (o Operator) getName() (string, error) {
	enr, err := p2p.DecodeENR(o.ENR)
	if err != nil {
		return "", errors.Wrap(err, "decode enr", z.Str("enr", o.ENR))
	}

	var pk enode.Secp256k1
	if err := enr.Load(&pk); err != nil {
		return "", errors.Wrap(err, "load pubkey")
	}

	return randomName(ecdsa.PublicKey(pk)), nil
}

// HashTreeRoot ssz hashes the Definition object.
func (o Operator) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(o) //nolint:wrapcheck
}

// HashTreeRootWith ssz hashes the Operator object with a hasher.
func (o Operator) HashTreeRootWith(hh *ssz.Hasher) error {
	indx := hh.Index()

	// Field (0) 'Address'
	hh.PutBytes([]byte(o.Address))

	// Field (1) 'ENR'
	hh.PutBytes([]byte(o.ENR))

	// Field (2) 'Nonce'
	hh.PutUint64(uint64(o.Nonce))

	// Field (3) 'ENRSignature'
	hh.PutBytes(o.ENRSignature)

	hh.Merkleize(indx)

	return nil
}

// randomName returns a deterministic name for an ecdsa public key. The name consists of a noun
// and an adjective separated by a hyphen. The noun is calculated using PublicKey's X coordinate
// while the adjective is calculated using PublicKey's Y coordinate.
func randomName(pk ecdsa.PublicKey) string {
	// list of 225 adjectives
	adjectives := []string{"adorable", "adventurous", "aggressive", "agreeable", "alert", "alive", "amused", "angry", "annoyed", "annoying", "anxious", "arrogant", "ashamed", "attractive", "average", "awful", "bad", "beautiful", "better", "bewildered", "black", "bloody", "blue", "blushing", "bored", "brainy", "brave", "breakable", "bright", "busy", "calm", "careful", "cautious", "charming", "cheerful", "clean", "clear", "clever", "cloudy", "clumsy", "colorful", "combative", "comfortable", "concerned", "condemned", "confused", "cooperative", "courageous", "crazy", "creepy", "crowded", "cruel", "curious", "cute", "dangerous", "dark", "dead", "defeated", "defiant", "delightful", "depressed", "determined", "different", "difficult", "disgusted", "distinct", "disturbed", "dizzy", "doubtful", "drab", "dull", "eager", "easy", "elated", "elegant", "embarrassed", "enchanting", "encouraging", "energetic", "enthusiastic", "envious", "evil", "excited", "expensive", "exuberant", "fair", "faithful", "famous", "fancy", "fantastic", "fierce", "filthy", "fine", "foolish", "fragile", "frail", "frantic", "friendly", "frightened", "funny", "gentle", "gifted", "glamorous", "gleaming", "glorious", "good", "gorgeous", "graceful", "grieving", "grotesque", "grumpy", "handsome", "happy", "healthy", "helpful", "helpless", "hilarious", "homeless", "homely", "horrible", "hungry", "hurt", "ill", "important", "impossible", "inexpensive", "innocent", "inquisitive", "itchy", "jealous", "jittery", "jolly", "joyous", "kind", "lazy", "light", "lively", "lonely", "long", "lovely", "lucky", "magnificent", "misty", "modern", "motionless", "muddy", "mushy", "mysterious", "nasty", "naughty", "nervous", "nice", "nutty", "obedient", "obnoxious", "odd", "open", "outrageous", "outstanding", "panicky", "perfect", "plain", "pleasant", "poised", "poor", "powerful", "precious", "prickly", "proud", "putrid", "puzzled", "quaint", "real", "relieved", "repulsive", "rich", "scary", "selfish", "shiny", "shy", "silly", "sleepy", "smiling", "smoggy", "sore", "sparkling", "splendid", "spotless", "stormy", "strange", "stupid", "successful", "super", "talented", "tame", "tasty", "tender", "tense", "terrible", "thankful", "thoughtful", "thoughtless", "tired", "tough", "troubled", "ugliest", "ugly", "uninterested", "unsightly", "unusual", "upset", "uptight", "vast", "victorious", "vivacious", "wandering", "weary", "wicked", "wild", "witty", "worried", "worrisome", "wrong", "zany", "zealous"}
	// list of 144 nouns
	nouns := []string{"adult", "age", "amount", "area", "back", "bed", "blood", "body", "book", "box", "boy", "bulb", "bunch", "business", "camera", "chicken", "child", "chocolates", "city", "clothes", "colony", "colors", "company", "computer", "continent", "council", "country", "course", "cycle", "dates", "day", "death", "desk", "door", "egg", "face", "fact", "factory", "family", "farm", "farmer", "father", "fish", "floor", "flowers", "food", "fridge", "future", "game", "garden", "gas", "glass", "group", "health", "hill", "hospital", "idea", "image", "industry", "island", "jewelry", "job", "kitchen", "land", "law", "leaves", "leg", "letter", "life", "magazine", "market", "metal", "mirror", "mobile", "money", "morning", "mother", "mountain", "movie", "name", "nest", "news", "ocean", "oil", "painter", "park", "party", "pen", "pen", "pencil", "person", "picture", "pillow", "place", "plant", "pond", "rain", "rate", "result", "ring", "road", "rock", "rocket", "room", "rope", "rule", "sale", "school", "shape", "shapes", "ship", "shop", "sister", "site", "skin", "snacks", "son", "song", "sort", "sound", "soup", "sports", "state", "stone", "street", "system", "taxi", "tea", "teacher", "team", "toy", "tractor", "trade", "train", "video", "view", "water", "waterfall", "week", "women", "wood", "word", "year", "yesterday"}

	res := big.NewInt(0)

	// calculate the index of the adjective using X % ADJ_LEN
	adjLen := big.NewInt(int64(len(adjectives)))
	res.Rem(pk.X, adjLen)
	adjIdx := res.Uint64()

	// similarly, calculate the index of the noun using Y % NOUN_LEN
	nounLen := big.NewInt(int64(len(nouns)))
	nounIdx := res.Rem(pk.Y, nounLen).Uint64()

	return fmt.Sprintf("%s-%s", adjectives[adjIdx], nouns[nounIdx])
}
