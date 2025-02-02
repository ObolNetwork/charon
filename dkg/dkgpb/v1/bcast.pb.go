// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.4
// 	protoc        (unknown)
// source: dkg/dkgpb/v1/bcast.proto

package v1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	anypb "google.golang.org/protobuf/types/known/anypb"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type BCastSigRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Id            string                 `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Message       *anypb.Any             `protobuf:"bytes,3,opt,name=message,proto3" json:"message,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *BCastSigRequest) Reset() {
	*x = BCastSigRequest{}
	mi := &file_dkg_dkgpb_v1_bcast_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *BCastSigRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BCastSigRequest) ProtoMessage() {}

func (x *BCastSigRequest) ProtoReflect() protoreflect.Message {
	mi := &file_dkg_dkgpb_v1_bcast_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BCastSigRequest.ProtoReflect.Descriptor instead.
func (*BCastSigRequest) Descriptor() ([]byte, []int) {
	return file_dkg_dkgpb_v1_bcast_proto_rawDescGZIP(), []int{0}
}

func (x *BCastSigRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *BCastSigRequest) GetMessage() *anypb.Any {
	if x != nil {
		return x.Message
	}
	return nil
}

type BCastSigResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Id            string                 `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Signature     []byte                 `protobuf:"bytes,2,opt,name=signature,proto3" json:"signature,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *BCastSigResponse) Reset() {
	*x = BCastSigResponse{}
	mi := &file_dkg_dkgpb_v1_bcast_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *BCastSigResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BCastSigResponse) ProtoMessage() {}

func (x *BCastSigResponse) ProtoReflect() protoreflect.Message {
	mi := &file_dkg_dkgpb_v1_bcast_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BCastSigResponse.ProtoReflect.Descriptor instead.
func (*BCastSigResponse) Descriptor() ([]byte, []int) {
	return file_dkg_dkgpb_v1_bcast_proto_rawDescGZIP(), []int{1}
}

func (x *BCastSigResponse) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *BCastSigResponse) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

type BCastMessage struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Id            string                 `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Message       *anypb.Any             `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty"`
	Signatures    [][]byte               `protobuf:"bytes,3,rep,name=signatures,proto3" json:"signatures,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *BCastMessage) Reset() {
	*x = BCastMessage{}
	mi := &file_dkg_dkgpb_v1_bcast_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *BCastMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BCastMessage) ProtoMessage() {}

func (x *BCastMessage) ProtoReflect() protoreflect.Message {
	mi := &file_dkg_dkgpb_v1_bcast_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BCastMessage.ProtoReflect.Descriptor instead.
func (*BCastMessage) Descriptor() ([]byte, []int) {
	return file_dkg_dkgpb_v1_bcast_proto_rawDescGZIP(), []int{2}
}

func (x *BCastMessage) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *BCastMessage) GetMessage() *anypb.Any {
	if x != nil {
		return x.Message
	}
	return nil
}

func (x *BCastMessage) GetSignatures() [][]byte {
	if x != nil {
		return x.Signatures
	}
	return nil
}

var File_dkg_dkgpb_v1_bcast_proto protoreflect.FileDescriptor

var file_dkg_dkgpb_v1_bcast_proto_rawDesc = string([]byte{
	0x0a, 0x18, 0x64, 0x6b, 0x67, 0x2f, 0x64, 0x6b, 0x67, 0x70, 0x62, 0x2f, 0x76, 0x31, 0x2f, 0x62,
	0x63, 0x61, 0x73, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0c, 0x64, 0x6b, 0x67, 0x2e,
	0x64, 0x6b, 0x67, 0x70, 0x62, 0x2e, 0x76, 0x31, 0x1a, 0x19, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x61, 0x6e, 0x79, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0x57, 0x0a, 0x0f, 0x42, 0x43, 0x61, 0x73, 0x74, 0x53, 0x69, 0x67, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x2e, 0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67,
	0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x41, 0x6e, 0x79, 0x52, 0x07, 0x6d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x4a, 0x04, 0x08, 0x02, 0x10, 0x03, 0x22, 0x40, 0x0a, 0x10,
	0x42, 0x43, 0x61, 0x73, 0x74, 0x53, 0x69, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64,
	0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x22, 0x6e,
	0x0a, 0x0c, 0x42, 0x43, 0x61, 0x73, 0x74, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x0e,
	0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x2e,
	0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x14, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x41, 0x6e, 0x79, 0x52, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x1e,
	0x0a, 0x0a, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x18, 0x03, 0x20, 0x03,
	0x28, 0x0c, 0x52, 0x0a, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x42, 0x2c,
	0x5a, 0x2a, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x62, 0x6f,
	0x6c, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2f, 0x63, 0x68, 0x61, 0x72, 0x6f, 0x6e, 0x2f,
	0x64, 0x6b, 0x67, 0x2f, 0x64, 0x6b, 0x67, 0x70, 0x62, 0x2f, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
})

var (
	file_dkg_dkgpb_v1_bcast_proto_rawDescOnce sync.Once
	file_dkg_dkgpb_v1_bcast_proto_rawDescData []byte
)

func file_dkg_dkgpb_v1_bcast_proto_rawDescGZIP() []byte {
	file_dkg_dkgpb_v1_bcast_proto_rawDescOnce.Do(func() {
		file_dkg_dkgpb_v1_bcast_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_dkg_dkgpb_v1_bcast_proto_rawDesc), len(file_dkg_dkgpb_v1_bcast_proto_rawDesc)))
	})
	return file_dkg_dkgpb_v1_bcast_proto_rawDescData
}

var file_dkg_dkgpb_v1_bcast_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_dkg_dkgpb_v1_bcast_proto_goTypes = []any{
	(*BCastSigRequest)(nil),  // 0: dkg.dkgpb.v1.BCastSigRequest
	(*BCastSigResponse)(nil), // 1: dkg.dkgpb.v1.BCastSigResponse
	(*BCastMessage)(nil),     // 2: dkg.dkgpb.v1.BCastMessage
	(*anypb.Any)(nil),        // 3: google.protobuf.Any
}
var file_dkg_dkgpb_v1_bcast_proto_depIdxs = []int32{
	3, // 0: dkg.dkgpb.v1.BCastSigRequest.message:type_name -> google.protobuf.Any
	3, // 1: dkg.dkgpb.v1.BCastMessage.message:type_name -> google.protobuf.Any
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_dkg_dkgpb_v1_bcast_proto_init() }
func file_dkg_dkgpb_v1_bcast_proto_init() {
	if File_dkg_dkgpb_v1_bcast_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_dkg_dkgpb_v1_bcast_proto_rawDesc), len(file_dkg_dkgpb_v1_bcast_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_dkg_dkgpb_v1_bcast_proto_goTypes,
		DependencyIndexes: file_dkg_dkgpb_v1_bcast_proto_depIdxs,
		MessageInfos:      file_dkg_dkgpb_v1_bcast_proto_msgTypes,
	}.Build()
	File_dkg_dkgpb_v1_bcast_proto = out.File
	file_dkg_dkgpb_v1_bcast_proto_goTypes = nil
	file_dkg_dkgpb_v1_bcast_proto_depIdxs = nil
}
