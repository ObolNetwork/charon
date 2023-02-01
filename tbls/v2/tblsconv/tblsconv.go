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

package tblsconv

import (
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/obolnetwork/charon/core"
	v2 "github.com/obolnetwork/charon/tbls/v2"
)

// SigFromCore converts a core workflow Signature type into a tbls.Signature.
func SigFromCore(sig core.Signature) v2.Signature {
	rawSig := (*[96]byte)(sig.Signature())
	return *rawSig
}

// SigToCore converts a tbls.Signature into a core workflow Signature type.
func SigToCore(sig v2.Signature) core.Signature {
	return core.SigFromETH2(eth2p0.BLSSignature(sig))
}

// SigToETH2 converts a tbls.Signature into an eth2 phase0 bls signature.
func SigToETH2(sig v2.Signature) eth2p0.BLSSignature {
	return eth2p0.BLSSignature(sig)
}
