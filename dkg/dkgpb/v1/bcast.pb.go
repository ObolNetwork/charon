// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
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

const file_dkg_dkgpb_v1_bcast_proto_rawDesc = "" +
	"\n" +
	"\x18dkg/dkgpb/v1/bcast.proto\x12\fdkg.dkgpb.v1\x1a\x19google/protobuf/any.proto\"W\n" +
	"\x0fBCastSigRequest\x12\x0e\n" +
	"\x02id\x18\x01 \x01(\tR\x02id\x12.\n" +
	"\amessage\x18\x03 \x01(\v2\x14.google.protobuf.AnyR\amessageJ\x04\b\x02\x10\x03\"@\n" +
	"\x10BCastSigResponse\x12\x0e\n" +
	"\x02id\x18\x01 \x01(\tR\x02id\x12\x1c\n" +
	"\tsignature\x18\x02 \x01(\fR\tsignature\"n\n" +
	"\fBCastMessage\x12\x0e\n" +
	"\x02id\x18\x01 \x01(\tR\x02id\x12.\n" +
	"\amessage\x18\x02 \x01(\v2\x14.google.protobuf.AnyR\amessage\x12\x1e\n" +
	"\n" +
	"signatures\x18\x03 \x03(\fR\n" +
	"signaturesB,Z*github.com/obolnetwork/charon/dkg/dkgpb/v1b\x06proto3"

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
