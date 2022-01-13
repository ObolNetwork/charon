// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             (unknown)
// source: api/control_plane.proto

package api

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// ControlPlaneClient is the client API for ControlPlane service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ControlPlaneClient interface {
	GetSelf(ctx context.Context, in *GetSelfRequest, opts ...grpc.CallOption) (*GetSelfResponse, error)
	GetPeers(ctx context.Context, in *GetPeersRequest, opts ...grpc.CallOption) (*GetPeersResponse, error)
}

type controlPlaneClient struct {
	cc grpc.ClientConnInterface
}

func NewControlPlaneClient(cc grpc.ClientConnInterface) ControlPlaneClient {
	return &controlPlaneClient{cc}
}

func (c *controlPlaneClient) GetSelf(ctx context.Context, in *GetSelfRequest, opts ...grpc.CallOption) (*GetSelfResponse, error) {
	out := new(GetSelfResponse)
	err := c.cc.Invoke(ctx, "/obol.v1.charon.ControlPlane/GetSelf", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *controlPlaneClient) GetPeers(ctx context.Context, in *GetPeersRequest, opts ...grpc.CallOption) (*GetPeersResponse, error) {
	out := new(GetPeersResponse)
	err := c.cc.Invoke(ctx, "/obol.v1.charon.ControlPlane/GetPeers", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ControlPlaneServer is the server API for ControlPlane service.
// All implementations must embed UnimplementedControlPlaneServer
// for forward compatibility
type ControlPlaneServer interface {
	GetSelf(context.Context, *GetSelfRequest) (*GetSelfResponse, error)
	GetPeers(context.Context, *GetPeersRequest) (*GetPeersResponse, error)
	mustEmbedUnimplementedControlPlaneServer()
}

// UnimplementedControlPlaneServer must be embedded to have forward compatible implementations.
type UnimplementedControlPlaneServer struct {
}

func (UnimplementedControlPlaneServer) GetSelf(context.Context, *GetSelfRequest) (*GetSelfResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetSelf not implemented")
}
func (UnimplementedControlPlaneServer) GetPeers(context.Context, *GetPeersRequest) (*GetPeersResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetPeers not implemented")
}
func (UnimplementedControlPlaneServer) mustEmbedUnimplementedControlPlaneServer() {}

// UnsafeControlPlaneServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ControlPlaneServer will
// result in compilation errors.
type UnsafeControlPlaneServer interface {
	mustEmbedUnimplementedControlPlaneServer()
}

func RegisterControlPlaneServer(s grpc.ServiceRegistrar, srv ControlPlaneServer) {
	s.RegisterService(&ControlPlane_ServiceDesc, srv)
}

func _ControlPlane_GetSelf_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetSelfRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ControlPlaneServer).GetSelf(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/obol.v1.charon.ControlPlane/GetSelf",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ControlPlaneServer).GetSelf(ctx, req.(*GetSelfRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ControlPlane_GetPeers_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetPeersRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ControlPlaneServer).GetPeers(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/obol.v1.charon.ControlPlane/GetPeers",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ControlPlaneServer).GetPeers(ctx, req.(*GetPeersRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// ControlPlane_ServiceDesc is the grpc.ServiceDesc for ControlPlane service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ControlPlane_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "obol.v1.charon.ControlPlane",
	HandlerType: (*ControlPlaneServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetSelf",
			Handler:    _ControlPlane_GetSelf_Handler,
		},
		{
			MethodName: "GetPeers",
			Handler:    _ControlPlane_GetPeers_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api/control_plane.proto",
}
