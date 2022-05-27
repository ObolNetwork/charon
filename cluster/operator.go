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
	"fmt"
	"github.com/ethereum/go-ethereum/p2p/enode"
	ssz "github.com/ferranbt/fastssz"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/p2p"
	"math/rand"
	"time"

	"github.com/obolnetwork/charon/app/errors"
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

func (o Operator) getName() (string, error) {
	enr, err := p2p.DecodeENR(o.ENR)
	if err != nil {
		return "", errors.Wrap(err, "decode enr", z.Str("enr", o.ENR))
	}
	var pk enode.Secp256k1
	if err := enr.Load(&pk); err != nil {
		return "", errors.Wrap(err, "load pubkey")
	}
	return "", nil
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

// randomOperatorName returns a random string identifying an operator.
func randomOperatorName() string {
	// list of 225 adjectives
	adjectives := []string{"adorable", "adventurous", "aggressive", "agreeable", "alert", "alive", "amused", "angry", "annoyed", "annoying", "anxious", "arrogant", "ashamed", "attractive", "average", "awful", "bad", "beautiful", "better", "bewildered", "black", "bloody", "blue", "blushing", "bored", "brainy", "brave", "breakable", "bright", "busy", "calm", "careful", "cautious", "charming", "cheerful", "clean", "clear", "clever", "cloudy", "clumsy", "colorful", "combative", "comfortable", "concerned", "condemned", "confused", "cooperative", "courageous", "crazy", "creepy", "crowded", "cruel", "curious", "cute", "dangerous", "dark", "dead", "defeated", "defiant", "delightful", "depressed", "determined", "different", "difficult", "disgusted", "distinct", "disturbed", "dizzy", "doubtful", "drab", "dull", "eager", "easy", "elated", "elegant", "embarrassed", "enchanting", "encouraging", "energetic", "enthusiastic", "envious", "evil", "excited", "expensive", "exuberant", "fair", "faithful", "famous", "fancy", "fantastic", "fierce", "filthy", "fine", "foolish", "fragile", "frail", "frantic", "friendly", "frightened", "funny", "gentle", "gifted", "glamorous", "gleaming", "glorious", "good", "gorgeous", "graceful", "grieving", "grotesque", "grumpy", "handsome", "happy", "healthy", "helpful", "helpless", "hilarious", "homeless", "homely", "horrible", "hungry", "hurt", "ill", "important", "impossible", "inexpensive", "innocent", "inquisitive", "itchy", "jealous", "jittery", "jolly", "joyous", "kind", "lazy", "light", "lively", "lonely", "long", "lovely", "lucky", "magnificent", "misty", "modern", "motionless", "muddy", "mushy", "mysterious", "nasty", "naughty", "nervous", "nice", "nutty", "obedient", "obnoxious", "odd", "open", "outrageous", "outstanding", "panicky", "perfect", "plain", "pleasant", "poised", "poor", "powerful", "precious", "prickly", "proud", "putrid", "puzzled", "quaint", "real", "relieved", "repulsive", "rich", "scary", "selfish", "shiny", "shy", "silly", "sleepy", "smiling", "smoggy", "sore", "sparkling", "splendid", "spotless", "stormy", "strange", "stupid", "successful", "super", "talented", "tame", "tasty", "tender", "tense", "terrible", "thankful", "thoughtful", "thoughtless", "tired", "tough", "troubled", "ugliest", "ugly", "uninterested", "unsightly", "unusual", "upset", "uptight", "vast", "victorious", "vivacious", "wandering", "weary", "wicked", "wild", "witty", "worried", "worrisome", "wrong", "zany", "zealous"}

	// list of 144 nouns
	nouns := []string{"Adult", "Age", "Amount", "Area", "Back", "Bed", "Blood", "Body", "Book", "Box", "Boy", "Bulb", "Bunch", "Business", "Camera", "Chicken", "Child", "Chocolates", "City", "Clothes", "Colony", "Colors", "Company", "Computer", "Continent", "Council", "Country", "Course", "Cycle", "Dates", "Day", "Death", "Desk", "Door", "Egg", "Face", "Fact", "Factory", "Family", "Farm", "Farmer", "Father", "Fish", "Floor", "Flowers", "Food", "Fridge", "Future", "Game", "Garden", "Gas", "Glass", "Group", "Health", "Hill", "Hospital", "Idea", "Image", "Industry", "Island", "Jewelry", "Job", "Kitchen", "Land", "Law", "Leaves", "Leg", "Letter", "Life", "Magazine", "Market", "Metal", "Mirror", "Mobile", "Money", "Morning", "Mother", "Mountain", "Movie", "Name", "Nest", "News", "Ocean", "Oil", "Painter", "Park", "Party", "Pen", "Pen", "Pencil", "Person", "Picture", "Pillow", "Place", "Plant", "Pond", "Rain", "Rate", "Result", "Ring", "Road", "Rock", "Rocket", "Room", "Rope", "rule", "Sale", "School", "Shape", "Shapes", "Ship", "Shop", "Sister", "Site", "Skin", "Snacks", "Son", "Song", "Sort", "Sound", "Soup", "Sports", "State", "Stone", "Street", "System", "Taxi", "Tea", "Teacher", "Team", "Toy", "Tractor", "Trade", "Train", "Video", "View", "Water", "Waterfall", "Week", "Women", "Wood", "Word", "Year", "Yesterday"}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	adjIdx := r.Uint32() % uint32(len(adjectives))
	nounIdx := r.Uint32() % uint32(len(nouns))

	return fmt.Sprintf("%s-%s", adjectives[adjIdx], nouns[nounIdx])
}
