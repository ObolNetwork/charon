// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.35.2
// 	protoc        (unknown)
// source: dkg/dkgpb/v1/nodesigs.proto

package v1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type MsgNodeSig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Signature []byte `protobuf:"bytes,1,opt,name=signature,proto3" json:"signature,omitempty"`
	PeerIndex uint32 `protobuf:"varint,2,opt,name=peer_index,json=peerIndex,proto3" json:"peer_index,omitempty"`
}

func (x *MsgNodeSig) Reset() {
	*x = MsgNodeSig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_dkg_dkgpb_v1_nodesigs_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MsgNodeSig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MsgNodeSig) ProtoMessage() {}

func (x *MsgNodeSig) ProtoReflect() protoreflect.Message {
	mi := &file_dkg_dkgpb_v1_nodesigs_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MsgNodeSig.ProtoReflect.Descriptor instead.
func (*MsgNodeSig) Descriptor() ([]byte, []int) {
	return file_dkg_dkgpb_v1_nodesigs_proto_rawDescGZIP(), []int{0}
}

func (x *MsgNodeSig) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

func (x *MsgNodeSig) GetPeerIndex() uint32 {
	if x != nil {
		return x.PeerIndex
	}
	return 0
}

var File_dkg_dkgpb_v1_nodesigs_proto protoreflect.FileDescriptor

var file_dkg_dkgpb_v1_nodesigs_proto_rawDesc = []byte{
	0x0a, 0x1b, 0x64, 0x6b, 0x67, 0x2f, 0x64, 0x6b, 0x67, 0x70, 0x62, 0x2f, 0x76, 0x31, 0x2f, 0x6e,
	0x6f, 0x64, 0x65, 0x73, 0x69, 0x67, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0c, 0x64,
	0x6b, 0x67, 0x2e, 0x64, 0x6b, 0x67, 0x70, 0x62, 0x2e, 0x76, 0x31, 0x22, 0x49, 0x0a, 0x0a, 0x4d,
	0x73, 0x67, 0x4e, 0x6f, 0x64, 0x65, 0x53, 0x69, 0x67, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67,
	0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69,
	0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x65, 0x65, 0x72, 0x5f,
	0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x70, 0x65, 0x65,
	0x72, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x42, 0x2c, 0x5a, 0x2a, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62,
	0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x62, 0x6f, 0x6c, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b,
	0x2f, 0x63, 0x68, 0x61, 0x72, 0x6f, 0x6e, 0x2f, 0x64, 0x6b, 0x67, 0x2f, 0x64, 0x6b, 0x67, 0x70,
	0x62, 0x2f, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_dkg_dkgpb_v1_nodesigs_proto_rawDescOnce sync.Once
	file_dkg_dkgpb_v1_nodesigs_proto_rawDescData = file_dkg_dkgpb_v1_nodesigs_proto_rawDesc
)

func file_dkg_dkgpb_v1_nodesigs_proto_rawDescGZIP() []byte {
	file_dkg_dkgpb_v1_nodesigs_proto_rawDescOnce.Do(func() {
		file_dkg_dkgpb_v1_nodesigs_proto_rawDescData = protoimpl.X.CompressGZIP(file_dkg_dkgpb_v1_nodesigs_proto_rawDescData)
	})
	return file_dkg_dkgpb_v1_nodesigs_proto_rawDescData
}

var file_dkg_dkgpb_v1_nodesigs_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_dkg_dkgpb_v1_nodesigs_proto_goTypes = []any{
	(*MsgNodeSig)(nil), // 0: dkg.dkgpb.v1.MsgNodeSig
}
var file_dkg_dkgpb_v1_nodesigs_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_dkg_dkgpb_v1_nodesigs_proto_init() }
func file_dkg_dkgpb_v1_nodesigs_proto_init() {
	if File_dkg_dkgpb_v1_nodesigs_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_dkg_dkgpb_v1_nodesigs_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*MsgNodeSig); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_dkg_dkgpb_v1_nodesigs_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_dkg_dkgpb_v1_nodesigs_proto_goTypes,
		DependencyIndexes: file_dkg_dkgpb_v1_nodesigs_proto_depIdxs,
		MessageInfos:      file_dkg_dkgpb_v1_nodesigs_proto_msgTypes,
	}.Build()
	File_dkg_dkgpb_v1_nodesigs_proto = out.File
	file_dkg_dkgpb_v1_nodesigs_proto_rawDesc = nil
	file_dkg_dkgpb_v1_nodesigs_proto_goTypes = nil
	file_dkg_dkgpb_v1_nodesigs_proto_depIdxs = nil
}
