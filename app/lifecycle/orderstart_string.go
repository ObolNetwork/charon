// Code generated by "stringer -type=OrderStart -trimprefix=Start"; DO NOT EDIT.

package lifecycle

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[StartAggSigDB-0]
	_ = x[StartRelay-1]
	_ = x[StartMonitoringAPI-2]
	_ = x[StartValidatorAPI-3]
	_ = x[StartP2PPing-4]
	_ = x[StartP2PConsensus-5]
	_ = x[StartSimulator-6]
	_ = x[StartScheduler-7]
	_ = x[StartTracker-8]
}

const _OrderStart_name = "AggSigDBRelayMonitoringAPIValidatorAPIP2PPingP2PConsensusSimulatorSchedulerTracker"

var _OrderStart_index = [...]uint8{0, 8, 13, 26, 38, 45, 57, 66, 75, 82}

func (i OrderStart) String() string {
	if i < 0 || i >= OrderStart(len(_OrderStart_index)-1) {
		return "OrderStart(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _OrderStart_name[_OrderStart_index[i]:_OrderStart_index[i+1]]
}
