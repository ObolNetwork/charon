package cluster

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestRandomName(t *testing.T) {
	first := randomName()
	assert.True(t, strings.Contains(first, "-"))

	second := randomName()
	assert.True(t, strings.Contains(second, "-"))

	// Two random names must be different
	assert.NotEqual(t, first, second)
}
