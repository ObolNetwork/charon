package cluster

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestRandomOperatorName(t *testing.T) {
	got := randomOperatorName()
	assert.True(t, strings.Contains(got, "-"))
}
