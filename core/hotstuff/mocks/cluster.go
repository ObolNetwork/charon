// Code generated by mockery v2.42.1. DO NOT EDIT.

package mocks

import (
	hotstuff "github.com/obolnetwork/charon/core/hotstuff"
	mock "github.com/stretchr/testify/mock"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	time "time"
)

// Cluster is an autogenerated mock type for the Cluster type
type Cluster struct {
	mock.Mock
}

// HasQuorum provides a mock function with given fields: pubKeys
func (_m *Cluster) HasQuorum(pubKeys []*secp256k1.PublicKey) bool {
	ret := _m.Called(pubKeys)

	if len(ret) == 0 {
		panic("no return value specified for HasQuorum")
	}

	var r0 bool
	if rf, ok := ret.Get(0).(func([]*secp256k1.PublicKey) bool); ok {
		r0 = rf(pubKeys)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// Leader provides a mock function with given fields: view
func (_m *Cluster) Leader(view hotstuff.View) hotstuff.ID {
	ret := _m.Called(view)

	if len(ret) == 0 {
		panic("no return value specified for Leader")
	}

	var r0 hotstuff.ID
	if rf, ok := ret.Get(0).(func(hotstuff.View) hotstuff.ID); ok {
		r0 = rf(view)
	} else {
		r0 = ret.Get(0).(hotstuff.ID)
	}

	return r0
}

// MaxView provides a mock function with given fields:
func (_m *Cluster) MaxView() hotstuff.View {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for MaxView")
	}

	var r0 hotstuff.View
	if rf, ok := ret.Get(0).(func() hotstuff.View); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(hotstuff.View)
	}

	return r0
}

// PhaseTimeout provides a mock function with given fields:
func (_m *Cluster) PhaseTimeout() time.Duration {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for PhaseTimeout")
	}

	var r0 time.Duration
	if rf, ok := ret.Get(0).(func() time.Duration); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(time.Duration)
	}

	return r0
}

// PublicKeyToID provides a mock function with given fields: pubKey
func (_m *Cluster) PublicKeyToID(pubKey *secp256k1.PublicKey) hotstuff.ID {
	ret := _m.Called(pubKey)

	if len(ret) == 0 {
		panic("no return value specified for PublicKeyToID")
	}

	var r0 hotstuff.ID
	if rf, ok := ret.Get(0).(func(*secp256k1.PublicKey) hotstuff.ID); ok {
		r0 = rf(pubKey)
	} else {
		r0 = ret.Get(0).(hotstuff.ID)
	}

	return r0
}

// Threshold provides a mock function with given fields:
func (_m *Cluster) Threshold() uint {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Threshold")
	}

	var r0 uint
	if rf, ok := ret.Get(0).(func() uint); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(uint)
	}

	return r0
}

// NewCluster creates a new instance of Cluster. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewCluster(t interface {
	mock.TestingT
	Cleanup(func())
}) *Cluster {
	mock := &Cluster{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
