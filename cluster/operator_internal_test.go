package cluster

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestGetName(t *testing.T) {
	enr := "enr:-JG4QHBtkNsAMjMNpNpJS4flt2sfkpVoAtLAZXufe1R-vFZ8JSOkuWKyjqZMUuZhp8x0ye6b_j2vV2H_VXr_JPXaUKWGAYEEiHG5gmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQNmdSBrUavbjtQxixlaX-xcy4ci5k7swmRbEHBL-yQNzIN0Y3CCPoODdWRwgj6E"
	op := Operator{
		ENR: enr,
	}

	first, err := op.getName()
	assert.NoError(t, err)
	assert.True(t, strings.Contains(first, "-"))

	second, err := op.getName()
	assert.NoError(t, err)
	assert.True(t, strings.Contains(second, "-"))

	// The two names must be the same.
	assert.NotEqual(t, first, second)
}
