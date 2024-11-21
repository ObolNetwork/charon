// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.35.2
// 	protoc        (unknown)
// source: core/corepb/v1/priority.proto

package v1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	anypb "google.golang.org/protobuf/types/known/anypb"
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

	Msgs   []*PriorityMsg         `protobuf:"bytes,1,rep,name=msgs,proto3" json:"msgs,omitempty"`
	Topics []*PriorityTopicResult `protobuf:"bytes,2,rep,name=topics,proto3" json:"topics,omitempty"`
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
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Duty      *Duty                    `protobuf:"bytes,1,opt,name=duty,proto3" json:"duty,omitempty"`
	Topics    []*PriorityTopicProposal `protobuf:"bytes,2,rep,name=topics,proto3" json:"topics,omitempty"`
	PeerId    string                   `protobuf:"bytes,3,opt,name=peer_id,json=peerId,proto3" json:"peer_id,omitempty"`
	Signature []byte                   `protobuf:"bytes,4,opt,name=signature,proto3" json:"signature,omitempty"`
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
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Topic      *anypb.Any   `protobuf:"bytes,1,opt,name=topic,proto3" json:"topic,omitempty"`
	Priorities []*anypb.Any `protobuf:"bytes,2,rep,name=priorities,proto3" json:"priorities,omitempty"`
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
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Topic *anypb.Any `protobuf:"bytes,1,opt,name=topic,proto3" json:"topic,omitempty"`
	// priorities are ordered by decreasing score, ties are broken by peer with lowest peer ID.
	Priorities []*PriorityScoredResult `protobuf:"bytes,2,rep,name=priorities,proto3" json:"priorities,omitempty"`
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
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Priority *anypb.Any `protobuf:"bytes,1,opt,name=priority,proto3" json:"priority,omitempty"`
	Score    int64      `protobuf:"varint,2,opt,name=score,proto3" json:"score,omitempty"`
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

var file_core_corepb_v1_priority_proto_rawDesc = []byte{
	0x0a, 0x1d, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2f, 0x76, 0x31,
	0x2f, 0x70, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x0e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2e, 0x76, 0x31, 0x1a,
	0x19, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2f, 0x76, 0x31, 0x2f,
	0x63, 0x6f, 0x72, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x19, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x61, 0x6e, 0x79, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x7e, 0x0a, 0x0e, 0x50, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74,
	0x79, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x12, 0x2f, 0x0a, 0x04, 0x6d, 0x73, 0x67, 0x73, 0x18,
	0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x72,
	0x65, 0x70, 0x62, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x4d,
	0x73, 0x67, 0x52, 0x04, 0x6d, 0x73, 0x67, 0x73, 0x12, 0x3b, 0x0a, 0x06, 0x74, 0x6f, 0x70, 0x69,
	0x63, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x23, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e,
	0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x72, 0x69, 0x6f, 0x72, 0x69,
	0x74, 0x79, 0x54, 0x6f, 0x70, 0x69, 0x63, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x52, 0x06, 0x74,
	0x6f, 0x70, 0x69, 0x63, 0x73, 0x22, 0xad, 0x01, 0x0a, 0x0b, 0x50, 0x72, 0x69, 0x6f, 0x72, 0x69,
	0x74, 0x79, 0x4d, 0x73, 0x67, 0x12, 0x28, 0x0a, 0x04, 0x64, 0x75, 0x74, 0x79, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x70,
	0x62, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x75, 0x74, 0x79, 0x52, 0x04, 0x64, 0x75, 0x74, 0x79, 0x12,
	0x3d, 0x0a, 0x06, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x25, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2e, 0x76, 0x31,
	0x2e, 0x50, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x54, 0x6f, 0x70, 0x69, 0x63, 0x50, 0x72,
	0x6f, 0x70, 0x6f, 0x73, 0x61, 0x6c, 0x52, 0x06, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x73, 0x12, 0x17,
	0x0a, 0x07, 0x70, 0x65, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x06, 0x70, 0x65, 0x65, 0x72, 0x49, 0x64, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61,
	0x74, 0x75, 0x72, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e,
	0x61, 0x74, 0x75, 0x72, 0x65, 0x22, 0x79, 0x0a, 0x15, 0x50, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74,
	0x79, 0x54, 0x6f, 0x70, 0x69, 0x63, 0x50, 0x72, 0x6f, 0x70, 0x6f, 0x73, 0x61, 0x6c, 0x12, 0x2a,
	0x0a, 0x05, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x41, 0x6e, 0x79, 0x52, 0x05, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x12, 0x34, 0x0a, 0x0a, 0x70, 0x72,
	0x69, 0x6f, 0x72, 0x69, 0x74, 0x69, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x14,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x41, 0x6e, 0x79, 0x52, 0x0a, 0x70, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x69, 0x65, 0x73,
	0x22, 0x87, 0x01, 0x0a, 0x13, 0x50, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x54, 0x6f, 0x70,
	0x69, 0x63, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x12, 0x2a, 0x0a, 0x05, 0x74, 0x6f, 0x70, 0x69,
	0x63, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x41, 0x6e, 0x79, 0x52, 0x05, 0x74,
	0x6f, 0x70, 0x69, 0x63, 0x12, 0x44, 0x0a, 0x0a, 0x70, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x69,
	0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x24, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e,
	0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x72, 0x69, 0x6f, 0x72, 0x69,
	0x74, 0x79, 0x53, 0x63, 0x6f, 0x72, 0x65, 0x64, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x52, 0x0a,
	0x70, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x69, 0x65, 0x73, 0x22, 0x5e, 0x0a, 0x14, 0x50, 0x72,
	0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x53, 0x63, 0x6f, 0x72, 0x65, 0x64, 0x52, 0x65, 0x73, 0x75,
	0x6c, 0x74, 0x12, 0x30, 0x0a, 0x08, 0x70, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x41, 0x6e, 0x79, 0x52, 0x08, 0x70, 0x72, 0x69, 0x6f,
	0x72, 0x69, 0x74, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x63, 0x6f, 0x72, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x03, 0x52, 0x05, 0x73, 0x63, 0x6f, 0x72, 0x65, 0x42, 0x2e, 0x5a, 0x2c, 0x67, 0x69,
	0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x62, 0x6f, 0x6c, 0x6e, 0x65, 0x74,
	0x77, 0x6f, 0x72, 0x6b, 0x2f, 0x63, 0x68, 0x61, 0x72, 0x6f, 0x6e, 0x2f, 0x63, 0x6f, 0x72, 0x65,
	0x2f, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2f, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
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
			RawDescriptor: file_core_corepb_v1_priority_proto_rawDesc,
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
	file_core_corepb_v1_priority_proto_rawDesc = nil
	file_core_corepb_v1_priority_proto_goTypes = nil
	file_core_corepb_v1_priority_proto_depIdxs = nil
}
