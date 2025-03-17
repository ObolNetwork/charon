// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Code generated by mockery v2.42.1. DO NOT EDIT.

package mocks

import (
	context "context"

	ethclient "github.com/ethereum/go-ethereum/ethclient"

	mock "github.com/stretchr/testify/mock"
)

// Eth1Client is an autogenerated mock type for the Eth1Client type
type Eth1Client struct {
	mock.Mock
}

// BlockNumber provides a mock function with given fields: ctx
func (_m *Eth1Client) BlockNumber(ctx context.Context) (uint64, error) {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for BlockNumber")
	}

	var r0 uint64
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context) (uint64, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(context.Context) uint64); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Get(0).(uint64)
	}

	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Close provides a mock function with given fields:
func (_m *Eth1Client) Close() {
	_m.Called()
}

// GetClient provides a mock function with given fields:
func (_m *Eth1Client) GetClient() *ethclient.Client {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetClient")
	}

	var r0 *ethclient.Client
	if rf, ok := ret.Get(0).(func() *ethclient.Client); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*ethclient.Client)
		}
	}

	return r0
}

// NewEth1Client creates a new instance of Eth1Client. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewEth1Client(t interface {
	mock.TestingT
	Cleanup(func())
}) *Eth1Client {
	mock := &Eth1Client{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
