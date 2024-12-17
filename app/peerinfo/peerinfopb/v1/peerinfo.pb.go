// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.0
// 	protoc        (unknown)
// source: app/peerinfo/peerinfopb/v1/peerinfo.proto

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

type PeerInfo struct {
	state             protoimpl.MessageState `protogen:"open.v1"`
	CharonVersion     string                 `protobuf:"bytes,1,opt,name=charon_version,json=charonVersion,proto3" json:"charon_version,omitempty"`
	LockHash          []byte                 `protobuf:"bytes,2,opt,name=lock_hash,json=lockHash,proto3" json:"lock_hash,omitempty"`
	SentAt            *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=sent_at,json=sentAt,proto3,oneof" json:"sent_at,omitempty"`
	GitHash           string                 `protobuf:"bytes,4,opt,name=git_hash,json=gitHash,proto3" json:"git_hash,omitempty"`
	StartedAt         *timestamppb.Timestamp `protobuf:"bytes,5,opt,name=started_at,json=startedAt,proto3,oneof" json:"started_at,omitempty"`
	BuilderApiEnabled bool                   `protobuf:"varint,6,opt,name=builder_api_enabled,json=builderApiEnabled,proto3" json:"builder_api_enabled,omitempty"`
	Nickname          string                 `protobuf:"bytes,7,opt,name=nickname,proto3" json:"nickname,omitempty"`
	unknownFields     protoimpl.UnknownFields
	sizeCache         protoimpl.SizeCache
}

func (x *PeerInfo) Reset() {
	*x = PeerInfo{}
	mi := &file_app_peerinfo_peerinfopb_v1_peerinfo_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PeerInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PeerInfo) ProtoMessage() {}

func (x *PeerInfo) ProtoReflect() protoreflect.Message {
	mi := &file_app_peerinfo_peerinfopb_v1_peerinfo_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PeerInfo.ProtoReflect.Descriptor instead.
func (*PeerInfo) Descriptor() ([]byte, []int) {
	return file_app_peerinfo_peerinfopb_v1_peerinfo_proto_rawDescGZIP(), []int{0}
}

func (x *PeerInfo) GetCharonVersion() string {
	if x != nil {
		return x.CharonVersion
	}
	return ""
}

func (x *PeerInfo) GetLockHash() []byte {
	if x != nil {
		return x.LockHash
	}
	return nil
}

func (x *PeerInfo) GetSentAt() *timestamppb.Timestamp {
	if x != nil {
		return x.SentAt
	}
	return nil
}

func (x *PeerInfo) GetGitHash() string {
	if x != nil {
		return x.GitHash
	}
	return ""
}

func (x *PeerInfo) GetStartedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.StartedAt
	}
	return nil
}

func (x *PeerInfo) GetBuilderApiEnabled() bool {
	if x != nil {
		return x.BuilderApiEnabled
	}
	return false
}

func (x *PeerInfo) GetNickname() string {
	if x != nil {
		return x.Nickname
	}
	return ""
}

var File_app_peerinfo_peerinfopb_v1_peerinfo_proto protoreflect.FileDescriptor

var file_app_peerinfo_peerinfopb_v1_peerinfo_proto_rawDesc = []byte{
	0x0a, 0x29, 0x61, 0x70, 0x70, 0x2f, 0x70, 0x65, 0x65, 0x72, 0x69, 0x6e, 0x66, 0x6f, 0x2f, 0x70,
	0x65, 0x65, 0x72, 0x69, 0x6e, 0x66, 0x6f, 0x70, 0x62, 0x2f, 0x76, 0x31, 0x2f, 0x70, 0x65, 0x65,
	0x72, 0x69, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1a, 0x61, 0x70, 0x70,
	0x2e, 0x70, 0x65, 0x65, 0x72, 0x69, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x65, 0x65, 0x72, 0x69, 0x6e,
	0x66, 0x6f, 0x70, 0x62, 0x2e, 0x76, 0x31, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xca, 0x02, 0x0a, 0x08, 0x50, 0x65, 0x65,
	0x72, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x25, 0x0a, 0x0e, 0x63, 0x68, 0x61, 0x72, 0x6f, 0x6e, 0x5f,
	0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x63,
	0x68, 0x61, 0x72, 0x6f, 0x6e, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x1b, 0x0a, 0x09,
	0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x68, 0x61, 0x73, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x08, 0x6c, 0x6f, 0x63, 0x6b, 0x48, 0x61, 0x73, 0x68, 0x12, 0x38, 0x0a, 0x07, 0x73, 0x65, 0x6e,
	0x74, 0x5f, 0x61, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x48, 0x00, 0x52, 0x06, 0x73, 0x65, 0x6e, 0x74, 0x41, 0x74,
	0x88, 0x01, 0x01, 0x12, 0x19, 0x0a, 0x08, 0x67, 0x69, 0x74, 0x5f, 0x68, 0x61, 0x73, 0x68, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x67, 0x69, 0x74, 0x48, 0x61, 0x73, 0x68, 0x12, 0x3e,
	0x0a, 0x0a, 0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x48, 0x01,
	0x52, 0x09, 0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x64, 0x41, 0x74, 0x88, 0x01, 0x01, 0x12, 0x2e,
	0x0a, 0x13, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x65, 0x72, 0x5f, 0x61, 0x70, 0x69, 0x5f, 0x65, 0x6e,
	0x61, 0x62, 0x6c, 0x65, 0x64, 0x18, 0x06, 0x20, 0x01, 0x28, 0x08, 0x52, 0x11, 0x62, 0x75, 0x69,
	0x6c, 0x64, 0x65, 0x72, 0x41, 0x70, 0x69, 0x45, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x12, 0x1a,
	0x0a, 0x08, 0x6e, 0x69, 0x63, 0x6b, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x08, 0x6e, 0x69, 0x63, 0x6b, 0x6e, 0x61, 0x6d, 0x65, 0x42, 0x0a, 0x0a, 0x08, 0x5f, 0x73,
	0x65, 0x6e, 0x74, 0x5f, 0x61, 0x74, 0x42, 0x0d, 0x0a, 0x0b, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74,
	0x65, 0x64, 0x5f, 0x61, 0x74, 0x42, 0x3a, 0x5a, 0x38, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e,
	0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x62, 0x6f, 0x6c, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2f,
	0x63, 0x68, 0x61, 0x72, 0x6f, 0x6e, 0x2f, 0x61, 0x70, 0x70, 0x2f, 0x70, 0x65, 0x65, 0x72, 0x69,
	0x6e, 0x66, 0x6f, 0x2f, 0x70, 0x65, 0x65, 0x72, 0x69, 0x6e, 0x66, 0x6f, 0x70, 0x62, 0x2f, 0x76,
	0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_app_peerinfo_peerinfopb_v1_peerinfo_proto_rawDescOnce sync.Once
	file_app_peerinfo_peerinfopb_v1_peerinfo_proto_rawDescData = file_app_peerinfo_peerinfopb_v1_peerinfo_proto_rawDesc
)

func file_app_peerinfo_peerinfopb_v1_peerinfo_proto_rawDescGZIP() []byte {
	file_app_peerinfo_peerinfopb_v1_peerinfo_proto_rawDescOnce.Do(func() {
		file_app_peerinfo_peerinfopb_v1_peerinfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_app_peerinfo_peerinfopb_v1_peerinfo_proto_rawDescData)
	})
	return file_app_peerinfo_peerinfopb_v1_peerinfo_proto_rawDescData
}

var file_app_peerinfo_peerinfopb_v1_peerinfo_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_app_peerinfo_peerinfopb_v1_peerinfo_proto_goTypes = []any{
	(*PeerInfo)(nil),              // 0: app.peerinfo.peerinfopb.v1.PeerInfo
	(*timestamppb.Timestamp)(nil), // 1: google.protobuf.Timestamp
}
var file_app_peerinfo_peerinfopb_v1_peerinfo_proto_depIdxs = []int32{
	1, // 0: app.peerinfo.peerinfopb.v1.PeerInfo.sent_at:type_name -> google.protobuf.Timestamp
	1, // 1: app.peerinfo.peerinfopb.v1.PeerInfo.started_at:type_name -> google.protobuf.Timestamp
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_app_peerinfo_peerinfopb_v1_peerinfo_proto_init() }
func file_app_peerinfo_peerinfopb_v1_peerinfo_proto_init() {
	if File_app_peerinfo_peerinfopb_v1_peerinfo_proto != nil {
		return
	}
	file_app_peerinfo_peerinfopb_v1_peerinfo_proto_msgTypes[0].OneofWrappers = []any{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_app_peerinfo_peerinfopb_v1_peerinfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_app_peerinfo_peerinfopb_v1_peerinfo_proto_goTypes,
		DependencyIndexes: file_app_peerinfo_peerinfopb_v1_peerinfo_proto_depIdxs,
		MessageInfos:      file_app_peerinfo_peerinfopb_v1_peerinfo_proto_msgTypes,
	}.Build()
	File_app_peerinfo_peerinfopb_v1_peerinfo_proto = out.File
	file_app_peerinfo_peerinfopb_v1_peerinfo_proto_rawDesc = nil
	file_app_peerinfo_peerinfopb_v1_peerinfo_proto_goTypes = nil
	file_app_peerinfo_peerinfopb_v1_peerinfo_proto_depIdxs = nil
}
