// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        (unknown)
// source: core/corepb/v1/priority.proto

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

// PriorityResult defines a cluster wide priority result of the Prioritiser protocol.
type PriorityResult struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Msgs          []*PriorityMsg         `protobuf:"bytes,1,rep,name=msgs,proto3" json:"msgs,omitempty"`
	Topics        []*PriorityTopicResult `protobuf:"bytes,2,rep,name=topics,proto3" json:"topics,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *PriorityResult) Reset() {
	*x = PriorityResult{}
	mi := &file_core_corepb_v1_priority_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PriorityResult) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PriorityResult) ProtoMessage() {}

func (x *PriorityResult) ProtoReflect() protoreflect.Message {
	mi := &file_core_corepb_v1_priority_proto_msgTypes[0]
	if x != nil {
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

func (x *PriorityResult) GetTopics() []*PriorityTopicResult {
	if x != nil {
		return x.Topics
	}
	return nil
}

// PriorityMsg defines all the priorities and metadata of a single peer in the Prioritiser protocol.
type PriorityMsg struct {
	state         protoimpl.MessageState   `protogen:"open.v1"`
	Duty          *Duty                    `protobuf:"bytes,1,opt,name=duty,proto3" json:"duty,omitempty"`
	Topics        []*PriorityTopicProposal `protobuf:"bytes,2,rep,name=topics,proto3" json:"topics,omitempty"`
	PeerId        string                   `protobuf:"bytes,3,opt,name=peer_id,json=peerId,proto3" json:"peer_id,omitempty"`
	Signature     []byte                   `protobuf:"bytes,4,opt,name=signature,proto3" json:"signature,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *PriorityMsg) Reset() {
	*x = PriorityMsg{}
	mi := &file_core_corepb_v1_priority_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PriorityMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PriorityMsg) ProtoMessage() {}

func (x *PriorityMsg) ProtoReflect() protoreflect.Message {
	mi := &file_core_corepb_v1_priority_proto_msgTypes[1]
	if x != nil {
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

func (x *PriorityMsg) GetDuty() *Duty {
	if x != nil {
		return x.Duty
	}
	return nil
}

func (x *PriorityMsg) GetTopics() []*PriorityTopicProposal {
	if x != nil {
		return x.Topics
	}
	return nil
}

func (x *PriorityMsg) GetPeerId() string {
	if x != nil {
		return x.PeerId
	}
	return ""
}

func (x *PriorityMsg) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

// PriorityTopicProposal defines a single peers proposed priorities for a single topic in the Prioritiser protocol.
type PriorityTopicProposal struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Topic         *anypb.Any             `protobuf:"bytes,1,opt,name=topic,proto3" json:"topic,omitempty"`
	Priorities    []*anypb.Any           `protobuf:"bytes,2,rep,name=priorities,proto3" json:"priorities,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *PriorityTopicProposal) Reset() {
	*x = PriorityTopicProposal{}
	mi := &file_core_corepb_v1_priority_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PriorityTopicProposal) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PriorityTopicProposal) ProtoMessage() {}

func (x *PriorityTopicProposal) ProtoReflect() protoreflect.Message {
	mi := &file_core_corepb_v1_priority_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PriorityTopicProposal.ProtoReflect.Descriptor instead.
func (*PriorityTopicProposal) Descriptor() ([]byte, []int) {
	return file_core_corepb_v1_priority_proto_rawDescGZIP(), []int{2}
}

func (x *PriorityTopicProposal) GetTopic() *anypb.Any {
	if x != nil {
		return x.Topic
	}
	return nil
}

func (x *PriorityTopicProposal) GetPriorities() []*anypb.Any {
	if x != nil {
		return x.Priorities
	}
	return nil
}

// PriorityTopicResult defines the cluster wide resulting priorities for a
// single topic in the Prioritiser protocol.
type PriorityTopicResult struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	Topic *anypb.Any             `protobuf:"bytes,1,opt,name=topic,proto3" json:"topic,omitempty"`
	// priorities are ordered by decreasing score, ties are broken by peer with lowest peer ID.
	Priorities    []*PriorityScoredResult `protobuf:"bytes,2,rep,name=priorities,proto3" json:"priorities,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *PriorityTopicResult) Reset() {
	*x = PriorityTopicResult{}
	mi := &file_core_corepb_v1_priority_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PriorityTopicResult) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PriorityTopicResult) ProtoMessage() {}

func (x *PriorityTopicResult) ProtoReflect() protoreflect.Message {
	mi := &file_core_corepb_v1_priority_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PriorityTopicResult.ProtoReflect.Descriptor instead.
func (*PriorityTopicResult) Descriptor() ([]byte, []int) {
	return file_core_corepb_v1_priority_proto_rawDescGZIP(), []int{3}
}

func (x *PriorityTopicResult) GetTopic() *anypb.Any {
	if x != nil {
		return x.Topic
	}
	return nil
}

func (x *PriorityTopicResult) GetPriorities() []*PriorityScoredResult {
	if x != nil {
		return x.Priorities
	}
	return nil
}

// PriorityScoredResult defines the cluster wide priority score in the Prioritiser protocol.
type PriorityScoredResult struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Priority      *anypb.Any             `protobuf:"bytes,1,opt,name=priority,proto3" json:"priority,omitempty"`
	Score         int64                  `protobuf:"varint,2,opt,name=score,proto3" json:"score,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *PriorityScoredResult) Reset() {
	*x = PriorityScoredResult{}
	mi := &file_core_corepb_v1_priority_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PriorityScoredResult) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PriorityScoredResult) ProtoMessage() {}

func (x *PriorityScoredResult) ProtoReflect() protoreflect.Message {
	mi := &file_core_corepb_v1_priority_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PriorityScoredResult.ProtoReflect.Descriptor instead.
func (*PriorityScoredResult) Descriptor() ([]byte, []int) {
	return file_core_corepb_v1_priority_proto_rawDescGZIP(), []int{4}
}

func (x *PriorityScoredResult) GetPriority() *anypb.Any {
	if x != nil {
		return x.Priority
	}
	return nil
}

func (x *PriorityScoredResult) GetScore() int64 {
	if x != nil {
		return x.Score
	}
	return 0
}

var File_core_corepb_v1_priority_proto protoreflect.FileDescriptor

const file_core_corepb_v1_priority_proto_rawDesc = "" +
	"\n" +
	"\x1dcore/corepb/v1/priority.proto\x12\x0ecore.corepb.v1\x1a\x19core/corepb/v1/core.proto\x1a\x19google/protobuf/any.proto\"~\n" +
	"\x0ePriorityResult\x12/\n" +
	"\x04msgs\x18\x01 \x03(\v2\x1b.core.corepb.v1.PriorityMsgR\x04msgs\x12;\n" +
	"\x06topics\x18\x02 \x03(\v2#.core.corepb.v1.PriorityTopicResultR\x06topics\"\xad\x01\n" +
	"\vPriorityMsg\x12(\n" +
	"\x04duty\x18\x01 \x01(\v2\x14.core.corepb.v1.DutyR\x04duty\x12=\n" +
	"\x06topics\x18\x02 \x03(\v2%.core.corepb.v1.PriorityTopicProposalR\x06topics\x12\x17\n" +
	"\apeer_id\x18\x03 \x01(\tR\x06peerId\x12\x1c\n" +
	"\tsignature\x18\x04 \x01(\fR\tsignature\"y\n" +
	"\x15PriorityTopicProposal\x12*\n" +
	"\x05topic\x18\x01 \x01(\v2\x14.google.protobuf.AnyR\x05topic\x124\n" +
	"\n" +
	"priorities\x18\x02 \x03(\v2\x14.google.protobuf.AnyR\n" +
	"priorities\"\x87\x01\n" +
	"\x13PriorityTopicResult\x12*\n" +
	"\x05topic\x18\x01 \x01(\v2\x14.google.protobuf.AnyR\x05topic\x12D\n" +
	"\n" +
	"priorities\x18\x02 \x03(\v2$.core.corepb.v1.PriorityScoredResultR\n" +
	"priorities\"^\n" +
	"\x14PriorityScoredResult\x120\n" +
	"\bpriority\x18\x01 \x01(\v2\x14.google.protobuf.AnyR\bpriority\x12\x14\n" +
	"\x05score\x18\x02 \x01(\x03R\x05scoreB.Z,github.com/obolnetwork/charon/core/corepb/v1b\x06proto3"

var (
	file_core_corepb_v1_priority_proto_rawDescOnce sync.Once
	file_core_corepb_v1_priority_proto_rawDescData []byte
)

func file_core_corepb_v1_priority_proto_rawDescGZIP() []byte {
	file_core_corepb_v1_priority_proto_rawDescOnce.Do(func() {
		file_core_corepb_v1_priority_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_core_corepb_v1_priority_proto_rawDesc), len(file_core_corepb_v1_priority_proto_rawDesc)))
	})
	return file_core_corepb_v1_priority_proto_rawDescData
}

var file_core_corepb_v1_priority_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_core_corepb_v1_priority_proto_goTypes = []any{
	(*PriorityResult)(nil),        // 0: core.corepb.v1.PriorityResult
	(*PriorityMsg)(nil),           // 1: core.corepb.v1.PriorityMsg
	(*PriorityTopicProposal)(nil), // 2: core.corepb.v1.PriorityTopicProposal
	(*PriorityTopicResult)(nil),   // 3: core.corepb.v1.PriorityTopicResult
	(*PriorityScoredResult)(nil),  // 4: core.corepb.v1.PriorityScoredResult
	(*Duty)(nil),                  // 5: core.corepb.v1.Duty
	(*anypb.Any)(nil),             // 6: google.protobuf.Any
}
var file_core_corepb_v1_priority_proto_depIdxs = []int32{
	1, // 0: core.corepb.v1.PriorityResult.msgs:type_name -> core.corepb.v1.PriorityMsg
	3, // 1: core.corepb.v1.PriorityResult.topics:type_name -> core.corepb.v1.PriorityTopicResult
	5, // 2: core.corepb.v1.PriorityMsg.duty:type_name -> core.corepb.v1.Duty
	2, // 3: core.corepb.v1.PriorityMsg.topics:type_name -> core.corepb.v1.PriorityTopicProposal
	6, // 4: core.corepb.v1.PriorityTopicProposal.topic:type_name -> google.protobuf.Any
	6, // 5: core.corepb.v1.PriorityTopicProposal.priorities:type_name -> google.protobuf.Any
	6, // 6: core.corepb.v1.PriorityTopicResult.topic:type_name -> google.protobuf.Any
	4, // 7: core.corepb.v1.PriorityTopicResult.priorities:type_name -> core.corepb.v1.PriorityScoredResult
	6, // 8: core.corepb.v1.PriorityScoredResult.priority:type_name -> google.protobuf.Any
	9, // [9:9] is the sub-list for method output_type
	9, // [9:9] is the sub-list for method input_type
	9, // [9:9] is the sub-list for extension type_name
	9, // [9:9] is the sub-list for extension extendee
	0, // [0:9] is the sub-list for field type_name
}

func init() { file_core_corepb_v1_priority_proto_init() }
func file_core_corepb_v1_priority_proto_init() {
	if File_core_corepb_v1_priority_proto != nil {
		return
	}
	file_core_corepb_v1_core_proto_init()
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_core_corepb_v1_priority_proto_rawDesc), len(file_core_corepb_v1_priority_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_core_corepb_v1_priority_proto_goTypes,
		DependencyIndexes: file_core_corepb_v1_priority_proto_depIdxs,
		MessageInfos:      file_core_corepb_v1_priority_proto_msgTypes,
	}.Build()
	File_core_corepb_v1_priority_proto = out.File
	file_core_corepb_v1_priority_proto_goTypes = nil
	file_core_corepb_v1_priority_proto_depIdxs = nil
}
