package discovery

import (
	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/obolnetwork/charon/p2p"
)

// Peers keeps track about the node's own ENR and all other peers' ENRs.
type Peers struct {
	DB    *enode.DB
	Local *enode.LocalNode
}

func NewPeerDB(path string, config *p2p.Config, identity *ecdsa.PrivateKey) (*Peers, error) {
	db, err := enode.OpenDB(path)
	if err != nil {
		return nil, err
	}
	p := &Peers{DB: db}
	p.Local = enode.NewLocalNode(db, identity)
	if v4 := config.IPv4(); v4 != nil {
		p.Local.Set(enr.IPv4(v4))
	}
	if v6 := config.IPv6(); v6 != nil {
		p.Local.Set(enr.IPv4(v6))
	}
	p.Local.Set(enr.TCP(config.Port))
	return p, nil
}

func (c *Peers) Close() {
	c.Local = nil
	c.DB.Close()
	c.DB = nil
}
