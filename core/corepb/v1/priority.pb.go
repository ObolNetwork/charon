// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        (unknown)
// source: core/corepb/v1/priority.proto

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

// PriorityResult defines a cluster wide priority result of the Prioritiser protocol.
type PriorityResult struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Msgs   []*PriorityMsg   `protobuf:"bytes,1,rep,name=msgs,proto3" json:"msgs,omitempty"`
	Topics []*PriorityTopic `protobuf:"bytes,2,rep,name=topics,proto3" json:"topics,omitempty"`
}

func (x *PriorityResult) Reset() {
	*x = PriorityResult{}
	if protoimpl.UnsafeEnabled {
		mi := &file_core_corepb_v1_priority_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PriorityResult) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PriorityResult) ProtoMessage() {}

func (x *PriorityResult) ProtoReflect() protoreflect.Message {
	mi := &file_core_corepb_v1_priority_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PriorityResult.ProtoReflect.Descriptor instead.
func (*PriorityResult) Descriptor() ([]byte, []int) {
	return file_core_corepb_v1_priority_proto_rawDescGZIP(), []int{0}
}

func (x *PriorityResult) GetMsgs() []*PriorityMsg {
	if x != nil {
		return x.Msgs
	}
	return nil
}

func (x *PriorityResult) GetTopics() []*PriorityTopic {
	if x != nil {
		return x.Topics
	}
	return nil
}

// PriorityMsg defines all the priorities and metadata of a single peer in the Prioritiser protocol.
type PriorityMsg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Topics        []*PriorityTopic `protobuf:"bytes,1,rep,name=topics,proto3" json:"topics,omitempty"`
	Slot          int64            `protobuf:"varint,2,opt,name=slot,proto3" json:"slot,omitempty"`
	CharonVersion string           `protobuf:"bytes,3,opt,name=charon_version,json=charonVersion,proto3" json:"charon_version,omitempty"`
	LockHash      string           `protobuf:"bytes,4,opt,name=lock_hash,json=lockHash,proto3" json:"lock_hash,omitempty"`
	GoOs          string           `protobuf:"bytes,5,opt,name=go_os,json=goOs,proto3" json:"go_os,omitempty"`
	GoArch        string           `protobuf:"bytes,6,opt,name=go_arch,json=goArch,proto3" json:"go_arch,omitempty"`
	PeerId        string           `protobuf:"bytes,7,opt,name=peer_id,json=peerId,proto3" json:"peer_id,omitempty"`
	MsgHash       []byte           `protobuf:"bytes,8,opt,name=msg_hash,json=msgHash,proto3" json:"msg_hash,omitempty"`
	Signature     []byte           `protobuf:"bytes,9,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *PriorityMsg) Reset() {
	*x = PriorityMsg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_core_corepb_v1_priority_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PriorityMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PriorityMsg) ProtoMessage() {}

func (x *PriorityMsg) ProtoReflect() protoreflect.Message {
	mi := &file_core_corepb_v1_priority_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PriorityMsg.ProtoReflect.Descriptor instead.
func (*PriorityMsg) Descriptor() ([]byte, []int) {
	return file_core_corepb_v1_priority_proto_rawDescGZIP(), []int{1}
}

func (x *PriorityMsg) GetTopics() []*PriorityTopic {
	if x != nil {
		return x.Topics
	}
	return nil
}

func (x *PriorityMsg) GetSlot() int64 {
	if x != nil {
		return x.Slot
	}
	return 0
}

func (x *PriorityMsg) GetCharonVersion() string {
	if x != nil {
		return x.CharonVersion
	}
	return ""
}

func (x *PriorityMsg) GetLockHash() string {
	if x != nil {
		return x.LockHash
	}
	return ""
}

func (x *PriorityMsg) GetGoOs() string {
	if x != nil {
		return x.GoOs
	}
	return ""
}

func (x *PriorityMsg) GetGoArch() string {
	if x != nil {
		return x.GoArch
	}
	return ""
}

func (x *PriorityMsg) GetPeerId() string {
	if x != nil {
		return x.PeerId
	}
	return ""
}

func (x *PriorityMsg) GetMsgHash() []byte {
	if x != nil {
		return x.MsgHash
	}
	return nil
}

func (x *PriorityMsg) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

// PriorityTopic defines a single peers priorities for a single topic in the Prioritiser protocol.
type PriorityTopic struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Topic      string   `protobuf:"bytes,1,opt,name=topic,proto3" json:"topic,omitempty"`
	Priorities []string `protobuf:"bytes,2,rep,name=priorities,proto3" json:"priorities,omitempty"`
}

func (x *PriorityTopic) Reset() {
	*x = PriorityTopic{}
	if protoimpl.UnsafeEnabled {
		mi := &file_core_corepb_v1_priority_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PriorityTopic) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PriorityTopic) ProtoMessage() {}

func (x *PriorityTopic) ProtoReflect() protoreflect.Message {
	mi := &file_core_corepb_v1_priority_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PriorityTopic.ProtoReflect.Descriptor instead.
func (*PriorityTopic) Descriptor() ([]byte, []int) {
	return file_core_corepb_v1_priority_proto_rawDescGZIP(), []int{2}
}

func (x *PriorityTopic) GetTopic() string {
	if x != nil {
		return x.Topic
	}
	return ""
}

func (x *PriorityTopic) GetPriorities() []string {
	if x != nil {
		return x.Priorities
	}
	return nil
}

var File_core_corepb_v1_priority_proto protoreflect.FileDescriptor

var file_core_corepb_v1_priority_proto_rawDesc = []byte{
	0x0a, 0x1d, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2f, 0x76, 0x31,
	0x2f, 0x70, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x0e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2e, 0x76, 0x31, 0x22,
	0x78, 0x0a, 0x0e, 0x50, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x52, 0x65, 0x73, 0x75, 0x6c,
	0x74, 0x12, 0x2f, 0x0a, 0x04, 0x6d, 0x73, 0x67, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x1b, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2e, 0x76, 0x31,
	0x2e, 0x50, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x4d, 0x73, 0x67, 0x52, 0x04, 0x6d, 0x73,
	0x67, 0x73, 0x12, 0x35, 0x0a, 0x06, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x73, 0x18, 0x02, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x1d, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62,
	0x2e, 0x76, 0x31, 0x2e, 0x50, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x54, 0x6f, 0x70, 0x69,
	0x63, 0x52, 0x06, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x73, 0x22, 0x9c, 0x02, 0x0a, 0x0b, 0x50, 0x72,
	0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x4d, 0x73, 0x67, 0x12, 0x35, 0x0a, 0x06, 0x74, 0x6f, 0x70,
	0x69, 0x63, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1d, 0x2e, 0x63, 0x6f, 0x72, 0x65,
	0x2e, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x72, 0x69, 0x6f, 0x72,
	0x69, 0x74, 0x79, 0x54, 0x6f, 0x70, 0x69, 0x63, 0x52, 0x06, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x73,
	0x12, 0x12, 0x0a, 0x04, 0x73, 0x6c, 0x6f, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52, 0x04,
	0x73, 0x6c, 0x6f, 0x74, 0x12, 0x25, 0x0a, 0x0e, 0x63, 0x68, 0x61, 0x72, 0x6f, 0x6e, 0x5f, 0x76,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x63, 0x68,
	0x61, 0x72, 0x6f, 0x6e, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x1b, 0x0a, 0x09, 0x6c,
	0x6f, 0x63, 0x6b, 0x5f, 0x68, 0x61, 0x73, 0x68, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08,
	0x6c, 0x6f, 0x63, 0x6b, 0x48, 0x61, 0x73, 0x68, 0x12, 0x13, 0x0a, 0x05, 0x67, 0x6f, 0x5f, 0x6f,
	0x73, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x67, 0x6f, 0x4f, 0x73, 0x12, 0x17, 0x0a,
	0x07, 0x67, 0x6f, 0x5f, 0x61, 0x72, 0x63, 0x68, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06,
	0x67, 0x6f, 0x41, 0x72, 0x63, 0x68, 0x12, 0x17, 0x0a, 0x07, 0x70, 0x65, 0x65, 0x72, 0x5f, 0x69,
	0x64, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x70, 0x65, 0x65, 0x72, 0x49, 0x64, 0x12,
	0x19, 0x0a, 0x08, 0x6d, 0x73, 0x67, 0x5f, 0x68, 0x61, 0x73, 0x68, 0x18, 0x08, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x07, 0x6d, 0x73, 0x67, 0x48, 0x61, 0x73, 0x68, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69,
	0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73,
	0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x22, 0x45, 0x0a, 0x0d, 0x50, 0x72, 0x69, 0x6f,
	0x72, 0x69, 0x74, 0x79, 0x54, 0x6f, 0x70, 0x69, 0x63, 0x12, 0x14, 0x0a, 0x05, 0x74, 0x6f, 0x70,
	0x69, 0x63, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x12,
	0x1e, 0x0a, 0x0a, 0x70, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x69, 0x65, 0x73, 0x18, 0x02, 0x20,
	0x03, 0x28, 0x09, 0x52, 0x0a, 0x70, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x69, 0x65, 0x73, 0x42,
	0x2e, 0x5a, 0x2c, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x62,
	0x6f, 0x6c, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2f, 0x63, 0x68, 0x61, 0x72, 0x6f, 0x6e,
	0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2f, 0x76, 0x31, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_core_corepb_v1_priority_proto_rawDescOnce sync.Once
	file_core_corepb_v1_priority_proto_rawDescData = file_core_corepb_v1_priority_proto_rawDesc
)

func file_core_corepb_v1_priority_proto_rawDescGZIP() []byte {
	file_core_corepb_v1_priority_proto_rawDescOnce.Do(func() {
		file_core_corepb_v1_priority_proto_rawDescData = protoimpl.X.CompressGZIP(file_core_corepb_v1_priority_proto_rawDescData)
	})
	return file_core_corepb_v1_priority_proto_rawDescData
}

var file_core_corepb_v1_priority_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_core_corepb_v1_priority_proto_goTypes = []interface{}{
	(*PriorityResult)(nil), // 0: core.corepb.v1.PriorityResult
	(*PriorityMsg)(nil),    // 1: core.corepb.v1.PriorityMsg
	(*PriorityTopic)(nil),  // 2: core.corepb.v1.PriorityTopic
}
var file_core_corepb_v1_priority_proto_depIdxs = []int32{
	1, // 0: core.corepb.v1.PriorityResult.msgs:type_name -> core.corepb.v1.PriorityMsg
	2, // 1: core.corepb.v1.PriorityResult.topics:type_name -> core.corepb.v1.PriorityTopic
	2, // 2: core.corepb.v1.PriorityMsg.topics:type_name -> core.corepb.v1.PriorityTopic
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_core_corepb_v1_priority_proto_init() }
func file_core_corepb_v1_priority_proto_init() {
	if File_core_corepb_v1_priority_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_core_corepb_v1_priority_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PriorityResult); i {
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
		file_core_corepb_v1_priority_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PriorityMsg); i {
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
		file_core_corepb_v1_priority_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PriorityTopic); i {
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
			RawDescriptor: file_core_corepb_v1_priority_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_core_corepb_v1_priority_proto_goTypes,
		DependencyIndexes: file_core_corepb_v1_priority_proto_depIdxs,
		MessageInfos:      file_core_corepb_v1_priority_proto_msgTypes,
	}.Build()
	File_core_corepb_v1_priority_proto = out.File
	file_core_corepb_v1_priority_proto_rawDesc = nil
	file_core_corepb_v1_priority_proto_goTypes = nil
	file_core_corepb_v1_priority_proto_depIdxs = nil
}
