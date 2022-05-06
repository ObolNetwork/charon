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

// Code generated by "stringer -type=MsgType"; DO NOT EDIT.

package qbft

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[MsgPrePrepare-1]
	_ = x[MsgPrepare-2]
	_ = x[MsgCommit-3]
	_ = x[MsgRoundChange-4]
}

const _MsgType_name = "MsgPrePrepareMsgPrepareMsgCommitMsgRoundChange"

var _MsgType_index = [...]uint8{0, 13, 23, 32, 46}

func (i MsgType) String() string {
	i -= 1
	if i < 0 || i >= MsgType(len(_MsgType_index)-1) {
		return "MsgType(" + strconv.FormatInt(int64(i+1), 10) + ")"
	}
	return _MsgType_name[_MsgType_index[i]:_MsgType_index[i+1]]
}
