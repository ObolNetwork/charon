// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        (unknown)
// source: app/peerinfo/peerinfopb/v1/peerinfo.proto

package v1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
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

const file_app_peerinfo_peerinfopb_v1_peerinfo_proto_rawDesc = "" +
	"\n" +
	")app/peerinfo/peerinfopb/v1/peerinfo.proto\x12\x1aapp.peerinfo.peerinfopb.v1\x1a\x1fgoogle/protobuf/timestamp.proto\"\xca\x02\n" +
	"\bPeerInfo\x12%\n" +
	"\x0echaron_version\x18\x01 \x01(\tR\rcharonVersion\x12\x1b\n" +
	"\tlock_hash\x18\x02 \x01(\fR\blockHash\x128\n" +
	"\asent_at\x18\x03 \x01(\v2\x1a.google.protobuf.TimestampH\x00R\x06sentAt\x88\x01\x01\x12\x19\n" +
	"\bgit_hash\x18\x04 \x01(\tR\agitHash\x12>\n" +
	"\n" +
	"started_at\x18\x05 \x01(\v2\x1a.google.protobuf.TimestampH\x01R\tstartedAt\x88\x01\x01\x12.\n" +
	"\x13builder_api_enabled\x18\x06 \x01(\bR\x11builderApiEnabled\x12\x1a\n" +
	"\bnickname\x18\a \x01(\tR\bnicknameB\n" +
	"\n" +
	"\b_sent_atB\r\n" +
	"\v_started_atB:Z8github.com/obolnetwork/charon/app/peerinfo/peerinfopb/v1b\x06proto3"

var (
	file_app_peerinfo_peerinfopb_v1_peerinfo_proto_rawDescOnce sync.Once
	file_app_peerinfo_peerinfopb_v1_peerinfo_proto_rawDescData []byte
)

func file_app_peerinfo_peerinfopb_v1_peerinfo_proto_rawDescGZIP() []byte {
	file_app_peerinfo_peerinfopb_v1_peerinfo_proto_rawDescOnce.Do(func() {
		file_app_peerinfo_peerinfopb_v1_peerinfo_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_app_peerinfo_peerinfopb_v1_peerinfo_proto_rawDesc), len(file_app_peerinfo_peerinfopb_v1_peerinfo_proto_rawDesc)))
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
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_app_peerinfo_peerinfopb_v1_peerinfo_proto_rawDesc), len(file_app_peerinfo_peerinfopb_v1_peerinfo_proto_rawDesc)),
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
	file_app_peerinfo_peerinfopb_v1_peerinfo_proto_goTypes = nil
	file_app_peerinfo_peerinfopb_v1_peerinfo_proto_depIdxs = nil
}
