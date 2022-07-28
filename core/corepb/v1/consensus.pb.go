// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        (unknown)
// source: core/corepb/v1/consensus.proto

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

type QBFTMsg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type          int64            `protobuf:"varint,1,opt,name=type,proto3" json:"type,omitempty"`
	Duty          *Duty            `protobuf:"bytes,2,opt,name=duty,proto3" json:"duty,omitempty"`
	PeerIdx       int64            `protobuf:"varint,3,opt,name=peer_idx,json=peerIdx,proto3" json:"peer_idx,omitempty"`
	Round         int64            `protobuf:"varint,4,opt,name=round,proto3" json:"round,omitempty"`
	Value         *UnsignedDataSet `protobuf:"bytes,5,opt,name=value,proto3" json:"value,omitempty"`
	PreparedRound int64            `protobuf:"varint,6,opt,name=prepared_round,json=preparedRound,proto3" json:"prepared_round,omitempty"`
	PreparedValue *UnsignedDataSet `protobuf:"bytes,7,opt,name=prepared_value,json=preparedValue,proto3" json:"prepared_value,omitempty"`
	Signature     []byte           `protobuf:"bytes,8,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *QBFTMsg) Reset() {
	*x = QBFTMsg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_core_corepb_v1_consensus_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QBFTMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QBFTMsg) ProtoMessage() {}

func (x *QBFTMsg) ProtoReflect() protoreflect.Message {
	mi := &file_core_corepb_v1_consensus_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QBFTMsg.ProtoReflect.Descriptor instead.
func (*QBFTMsg) Descriptor() ([]byte, []int) {
	return file_core_corepb_v1_consensus_proto_rawDescGZIP(), []int{0}
}

func (x *QBFTMsg) GetType() int64 {
	if x != nil {
		return x.Type
	}
	return 0
}

func (x *QBFTMsg) GetDuty() *Duty {
	if x != nil {
		return x.Duty
	}
	return nil
}

func (x *QBFTMsg) GetPeerIdx() int64 {
	if x != nil {
		return x.PeerIdx
	}
	return 0
}

func (x *QBFTMsg) GetRound() int64 {
	if x != nil {
		return x.Round
	}
	return 0
}

func (x *QBFTMsg) GetValue() *UnsignedDataSet {
	if x != nil {
		return x.Value
	}
	return nil
}

func (x *QBFTMsg) GetPreparedRound() int64 {
	if x != nil {
		return x.PreparedRound
	}
	return 0
}

func (x *QBFTMsg) GetPreparedValue() *UnsignedDataSet {
	if x != nil {
		return x.PreparedValue
	}
	return nil
}

func (x *QBFTMsg) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

type ConsensusMsg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Msg           *QBFTMsg   `protobuf:"bytes,1,opt,name=msg,proto3" json:"msg,omitempty"`
	Justification []*QBFTMsg `protobuf:"bytes,2,rep,name=justification,proto3" json:"justification,omitempty"`
}

func (x *ConsensusMsg) Reset() {
	*x = ConsensusMsg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_core_corepb_v1_consensus_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConsensusMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConsensusMsg) ProtoMessage() {}

func (x *ConsensusMsg) ProtoReflect() protoreflect.Message {
	mi := &file_core_corepb_v1_consensus_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConsensusMsg.ProtoReflect.Descriptor instead.
func (*ConsensusMsg) Descriptor() ([]byte, []int) {
	return file_core_corepb_v1_consensus_proto_rawDescGZIP(), []int{1}
}

func (x *ConsensusMsg) GetMsg() *QBFTMsg {
	if x != nil {
		return x.Msg
	}
	return nil
}

func (x *ConsensusMsg) GetJustification() []*QBFTMsg {
	if x != nil {
		return x.Justification
	}
	return nil
}

var File_core_corepb_v1_consensus_proto protoreflect.FileDescriptor

var file_core_corepb_v1_consensus_proto_rawDesc = []byte{
	0x0a, 0x1e, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2f, 0x76, 0x31,
	0x2f, 0x63, 0x6f, 0x6e, 0x73, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x0e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2e, 0x76, 0x31,
	0x1a, 0x19, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2f, 0x76, 0x31,
	0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xbc, 0x02, 0x0a, 0x07,
	0x51, 0x42, 0x46, 0x54, 0x4d, 0x73, 0x67, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x28, 0x0a, 0x04, 0x64,
	0x75, 0x74, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x63, 0x6f, 0x72, 0x65,
	0x2e, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x75, 0x74, 0x79, 0x52,
	0x04, 0x64, 0x75, 0x74, 0x79, 0x12, 0x19, 0x0a, 0x08, 0x70, 0x65, 0x65, 0x72, 0x5f, 0x69, 0x64,
	0x78, 0x18, 0x03, 0x20, 0x01, 0x28, 0x03, 0x52, 0x07, 0x70, 0x65, 0x65, 0x72, 0x49, 0x64, 0x78,
	0x12, 0x14, 0x0a, 0x05, 0x72, 0x6f, 0x75, 0x6e, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x03, 0x52,
	0x05, 0x72, 0x6f, 0x75, 0x6e, 0x64, 0x12, 0x35, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18,
	0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x72,
	0x65, 0x70, 0x62, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x6e, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x44,
	0x61, 0x74, 0x61, 0x53, 0x65, 0x74, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x25, 0x0a,
	0x0e, 0x70, 0x72, 0x65, 0x70, 0x61, 0x72, 0x65, 0x64, 0x5f, 0x72, 0x6f, 0x75, 0x6e, 0x64, 0x18,
	0x06, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0d, 0x70, 0x72, 0x65, 0x70, 0x61, 0x72, 0x65, 0x64, 0x52,
	0x6f, 0x75, 0x6e, 0x64, 0x12, 0x46, 0x0a, 0x0e, 0x70, 0x72, 0x65, 0x70, 0x61, 0x72, 0x65, 0x64,
	0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x63,
	0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x6e,
	0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x44, 0x61, 0x74, 0x61, 0x53, 0x65, 0x74, 0x52, 0x0d, 0x70,
	0x72, 0x65, 0x70, 0x61, 0x72, 0x65, 0x64, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x1c, 0x0a, 0x09,
	0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x22, 0x78, 0x0a, 0x0c, 0x43, 0x6f,
	0x6e, 0x73, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x4d, 0x73, 0x67, 0x12, 0x29, 0x0a, 0x03, 0x6d, 0x73,
	0x67, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63,
	0x6f, 0x72, 0x65, 0x70, 0x62, 0x2e, 0x76, 0x31, 0x2e, 0x51, 0x42, 0x46, 0x54, 0x4d, 0x73, 0x67,
	0x52, 0x03, 0x6d, 0x73, 0x67, 0x12, 0x3d, 0x0a, 0x0d, 0x6a, 0x75, 0x73, 0x74, 0x69, 0x66, 0x69,
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x63,
	0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2e, 0x76, 0x31, 0x2e, 0x51, 0x42,
	0x46, 0x54, 0x4d, 0x73, 0x67, 0x52, 0x0d, 0x6a, 0x75, 0x73, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x42, 0x2e, 0x5a, 0x2c, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x6f, 0x62, 0x6f, 0x6c, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2f, 0x63,
	0x68, 0x61, 0x72, 0x6f, 0x6e, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x70,
	0x62, 0x2f, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_core_corepb_v1_consensus_proto_rawDescOnce sync.Once
	file_core_corepb_v1_consensus_proto_rawDescData = file_core_corepb_v1_consensus_proto_rawDesc
)

func file_core_corepb_v1_consensus_proto_rawDescGZIP() []byte {
	file_core_corepb_v1_consensus_proto_rawDescOnce.Do(func() {
		file_core_corepb_v1_consensus_proto_rawDescData = protoimpl.X.CompressGZIP(file_core_corepb_v1_consensus_proto_rawDescData)
	})
	return file_core_corepb_v1_consensus_proto_rawDescData
}

var file_core_corepb_v1_consensus_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_core_corepb_v1_consensus_proto_goTypes = []interface{}{
	(*QBFTMsg)(nil),         // 0: core.corepb.v1.QBFTMsg
	(*ConsensusMsg)(nil),    // 1: core.corepb.v1.ConsensusMsg
	(*Duty)(nil),            // 2: core.corepb.v1.Duty
	(*UnsignedDataSet)(nil), // 3: core.corepb.v1.UnsignedDataSet
}
var file_core_corepb_v1_consensus_proto_depIdxs = []int32{
	2, // 0: core.corepb.v1.QBFTMsg.duty:type_name -> core.corepb.v1.Duty
	3, // 1: core.corepb.v1.QBFTMsg.value:type_name -> core.corepb.v1.UnsignedDataSet
	3, // 2: core.corepb.v1.QBFTMsg.prepared_value:type_name -> core.corepb.v1.UnsignedDataSet
	0, // 3: core.corepb.v1.ConsensusMsg.msg:type_name -> core.corepb.v1.QBFTMsg
	0, // 4: core.corepb.v1.ConsensusMsg.justification:type_name -> core.corepb.v1.QBFTMsg
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_core_corepb_v1_consensus_proto_init() }
func file_core_corepb_v1_consensus_proto_init() {
	if File_core_corepb_v1_consensus_proto != nil {
		return
	}
	file_core_corepb_v1_core_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_core_corepb_v1_consensus_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QBFTMsg); i {
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
		file_core_corepb_v1_consensus_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConsensusMsg); i {
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
			RawDescriptor: file_core_corepb_v1_consensus_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_core_corepb_v1_consensus_proto_goTypes,
		DependencyIndexes: file_core_corepb_v1_consensus_proto_depIdxs,
		MessageInfos:      file_core_corepb_v1_consensus_proto_msgTypes,
	}.Build()
	File_core_corepb_v1_consensus_proto = out.File
	file_core_corepb_v1_consensus_proto_rawDesc = nil
	file_core_corepb_v1_consensus_proto_goTypes = nil
	file_core_corepb_v1_consensus_proto_depIdxs = nil
}
