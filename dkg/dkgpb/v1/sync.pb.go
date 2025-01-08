// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.2
// 	protoc        (unknown)
// source: dkg/dkgpb/v1/sync.proto

package v1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type MsgSync struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Timestamp     *timestamppb.Timestamp `protobuf:"bytes,1,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	HashSignature []byte                 `protobuf:"bytes,2,opt,name=hash_signature,json=hashSignature,proto3" json:"hash_signature,omitempty"`
	Shutdown      bool                   `protobuf:"varint,3,opt,name=shutdown,proto3" json:"shutdown,omitempty"`
	Version       string                 `protobuf:"bytes,4,opt,name=version,proto3" json:"version,omitempty"`
	Step          int64                  `protobuf:"varint,5,opt,name=step,proto3" json:"step,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *MsgSync) Reset() {
	*x = MsgSync{}
	mi := &file_dkg_dkgpb_v1_sync_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *MsgSync) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MsgSync) ProtoMessage() {}

func (x *MsgSync) ProtoReflect() protoreflect.Message {
	mi := &file_dkg_dkgpb_v1_sync_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MsgSync.ProtoReflect.Descriptor instead.
func (*MsgSync) Descriptor() ([]byte, []int) {
	return file_dkg_dkgpb_v1_sync_proto_rawDescGZIP(), []int{0}
}

func (x *MsgSync) GetTimestamp() *timestamppb.Timestamp {
	if x != nil {
		return x.Timestamp
	}
	return nil
}

func (x *MsgSync) GetHashSignature() []byte {
	if x != nil {
		return x.HashSignature
	}
	return nil
}

func (x *MsgSync) GetShutdown() bool {
	if x != nil {
		return x.Shutdown
	}
	return false
}

func (x *MsgSync) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *MsgSync) GetStep() int64 {
	if x != nil {
		return x.Step
	}
	return 0
}

type MsgSyncResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	SyncTimestamp *timestamppb.Timestamp `protobuf:"bytes,1,opt,name=sync_timestamp,json=syncTimestamp,proto3" json:"sync_timestamp,omitempty"`
	Error         string                 `protobuf:"bytes,2,opt,name=error,proto3" json:"error,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *MsgSyncResponse) Reset() {
	*x = MsgSyncResponse{}
	mi := &file_dkg_dkgpb_v1_sync_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *MsgSyncResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MsgSyncResponse) ProtoMessage() {}

func (x *MsgSyncResponse) ProtoReflect() protoreflect.Message {
	mi := &file_dkg_dkgpb_v1_sync_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MsgSyncResponse.ProtoReflect.Descriptor instead.
func (*MsgSyncResponse) Descriptor() ([]byte, []int) {
	return file_dkg_dkgpb_v1_sync_proto_rawDescGZIP(), []int{1}
}

func (x *MsgSyncResponse) GetSyncTimestamp() *timestamppb.Timestamp {
	if x != nil {
		return x.SyncTimestamp
	}
	return nil
}

func (x *MsgSyncResponse) GetError() string {
	if x != nil {
		return x.Error
	}
	return ""
}

var File_dkg_dkgpb_v1_sync_proto protoreflect.FileDescriptor

var file_dkg_dkgpb_v1_sync_proto_rawDesc = []byte{
	0x0a, 0x17, 0x64, 0x6b, 0x67, 0x2f, 0x64, 0x6b, 0x67, 0x70, 0x62, 0x2f, 0x76, 0x31, 0x2f, 0x73,
	0x79, 0x6e, 0x63, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0c, 0x64, 0x6b, 0x67, 0x2e, 0x64,
	0x6b, 0x67, 0x70, 0x62, 0x2e, 0x76, 0x31, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xb4, 0x01, 0x0a, 0x07, 0x4d, 0x73, 0x67,
	0x53, 0x79, 0x6e, 0x63, 0x12, 0x38, 0x0a, 0x09, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
	0x70, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x52, 0x09, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x12, 0x25,
	0x0a, 0x0e, 0x68, 0x61, 0x73, 0x68, 0x5f, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0d, 0x68, 0x61, 0x73, 0x68, 0x53, 0x69, 0x67, 0x6e,
	0x61, 0x74, 0x75, 0x72, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x73, 0x68, 0x75, 0x74, 0x64, 0x6f, 0x77,
	0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x08, 0x73, 0x68, 0x75, 0x74, 0x64, 0x6f, 0x77,
	0x6e, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x73,
	0x74, 0x65, 0x70, 0x18, 0x05, 0x20, 0x01, 0x28, 0x03, 0x52, 0x04, 0x73, 0x74, 0x65, 0x70, 0x22,
	0x6a, 0x0a, 0x0f, 0x4d, 0x73, 0x67, 0x53, 0x79, 0x6e, 0x63, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x41, 0x0a, 0x0e, 0x73, 0x79, 0x6e, 0x63, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x73,
	0x74, 0x61, 0x6d, 0x70, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0d, 0x73, 0x79, 0x6e, 0x63, 0x54, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x12, 0x14, 0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x42, 0x2c, 0x5a, 0x2a, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x62, 0x6f, 0x6c, 0x6e, 0x65,
	0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2f, 0x63, 0x68, 0x61, 0x72, 0x6f, 0x6e, 0x2f, 0x64, 0x6b, 0x67,
	0x2f, 0x64, 0x6b, 0x67, 0x70, 0x62, 0x2f, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_dkg_dkgpb_v1_sync_proto_rawDescOnce sync.Once
	file_dkg_dkgpb_v1_sync_proto_rawDescData = file_dkg_dkgpb_v1_sync_proto_rawDesc
)

func file_dkg_dkgpb_v1_sync_proto_rawDescGZIP() []byte {
	file_dkg_dkgpb_v1_sync_proto_rawDescOnce.Do(func() {
		file_dkg_dkgpb_v1_sync_proto_rawDescData = protoimpl.X.CompressGZIP(file_dkg_dkgpb_v1_sync_proto_rawDescData)
	})
	return file_dkg_dkgpb_v1_sync_proto_rawDescData
}

var file_dkg_dkgpb_v1_sync_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_dkg_dkgpb_v1_sync_proto_goTypes = []any{
	(*MsgSync)(nil),               // 0: dkg.dkgpb.v1.MsgSync
	(*MsgSyncResponse)(nil),       // 1: dkg.dkgpb.v1.MsgSyncResponse
	(*timestamppb.Timestamp)(nil), // 2: google.protobuf.Timestamp
}
var file_dkg_dkgpb_v1_sync_proto_depIdxs = []int32{
	2, // 0: dkg.dkgpb.v1.MsgSync.timestamp:type_name -> google.protobuf.Timestamp
	2, // 1: dkg.dkgpb.v1.MsgSyncResponse.sync_timestamp:type_name -> google.protobuf.Timestamp
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_dkg_dkgpb_v1_sync_proto_init() }
func file_dkg_dkgpb_v1_sync_proto_init() {
	if File_dkg_dkgpb_v1_sync_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_dkg_dkgpb_v1_sync_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_dkg_dkgpb_v1_sync_proto_goTypes,
		DependencyIndexes: file_dkg_dkgpb_v1_sync_proto_depIdxs,
		MessageInfos:      file_dkg_dkgpb_v1_sync_proto_msgTypes,
	}.Build()
	File_dkg_dkgpb_v1_sync_proto = out.File
	file_dkg_dkgpb_v1_sync_proto_rawDesc = nil
	file_dkg_dkgpb_v1_sync_proto_goTypes = nil
	file_dkg_dkgpb_v1_sync_proto_depIdxs = nil
}
