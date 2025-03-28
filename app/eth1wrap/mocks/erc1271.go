// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Code generated by mockery v2.42.1. DO NOT EDIT.

package mocks

import (
	bind "github.com/ethereum/go-ethereum/accounts/abi/bind"

	mock "github.com/stretchr/testify/mock"
)

// Erc1271 is an autogenerated mock type for the Erc1271 type
type Erc1271 struct {
	mock.Mock
}

// IsValidSignature provides a mock function with given fields: opts, hash, sig
func (_m *Erc1271) IsValidSignature(opts *bind.CallOpts, hash [32]byte, sig []byte) ([4]byte, error) {
	ret := _m.Called(opts, hash, sig)

	if len(ret) == 0 {
		panic("no return value specified for IsValidSignature")
	}

	var r0 [4]byte
	var r1 error
	if rf, ok := ret.Get(0).(func(*bind.CallOpts, [32]byte, []byte) ([4]byte, error)); ok {
		return rf(opts, hash, sig)
	}
	if rf, ok := ret.Get(0).(func(*bind.CallOpts, [32]byte, []byte) [4]byte); ok {
		r0 = rf(opts, hash, sig)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([4]byte)
		}
	}

	if rf, ok := ret.Get(1).(func(*bind.CallOpts, [32]byte, []byte) error); ok {
		r1 = rf(opts, hash, sig)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewErc1271 creates a new instance of Erc1271. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewErc1271(t interface {
	mock.TestingT
	Cleanup(func())
}) *Erc1271 {
	mock := &Erc1271{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
