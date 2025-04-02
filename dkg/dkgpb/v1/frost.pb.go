// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        (unknown)
// source: dkg/dkgpb/v1/frost.proto

package v1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
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

type FrostMsgKey struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	ValIdx        uint32                 `protobuf:"varint,1,opt,name=val_idx,json=valIdx,proto3" json:"val_idx,omitempty"`
	SourceId      uint32                 `protobuf:"varint,2,opt,name=source_id,json=sourceId,proto3" json:"source_id,omitempty"`
	TargetId      uint32                 `protobuf:"varint,3,opt,name=target_id,json=targetId,proto3" json:"target_id,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *FrostMsgKey) Reset() {
	*x = FrostMsgKey{}
	mi := &file_dkg_dkgpb_v1_frost_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *FrostMsgKey) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FrostMsgKey) ProtoMessage() {}

func (x *FrostMsgKey) ProtoReflect() protoreflect.Message {
	mi := &file_dkg_dkgpb_v1_frost_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FrostMsgKey.ProtoReflect.Descriptor instead.
func (*FrostMsgKey) Descriptor() ([]byte, []int) {
	return file_dkg_dkgpb_v1_frost_proto_rawDescGZIP(), []int{0}
}

func (x *FrostMsgKey) GetValIdx() uint32 {
	if x != nil {
		return x.ValIdx
	}
	return 0
}

func (x *FrostMsgKey) GetSourceId() uint32 {
	if x != nil {
		return x.SourceId
	}
	return 0
}

func (x *FrostMsgKey) GetTargetId() uint32 {
	if x != nil {
		return x.TargetId
	}
	return 0
}

type FrostRound1Casts struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Casts         []*FrostRound1Cast     `protobuf:"bytes,1,rep,name=casts,proto3" json:"casts,omitempty"` // One per validator
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *FrostRound1Casts) Reset() {
	*x = FrostRound1Casts{}
	mi := &file_dkg_dkgpb_v1_frost_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *FrostRound1Casts) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FrostRound1Casts) ProtoMessage() {}

func (x *FrostRound1Casts) ProtoReflect() protoreflect.Message {
	mi := &file_dkg_dkgpb_v1_frost_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FrostRound1Casts.ProtoReflect.Descriptor instead.
func (*FrostRound1Casts) Descriptor() ([]byte, []int) {
	return file_dkg_dkgpb_v1_frost_proto_rawDescGZIP(), []int{1}
}

func (x *FrostRound1Casts) GetCasts() []*FrostRound1Cast {
	if x != nil {
		return x.Casts
	}
	return nil
}

type FrostRound1Cast struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Key           *FrostMsgKey           `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Wi            []byte                 `protobuf:"bytes,2,opt,name=wi,proto3" json:"wi,omitempty"`
	Ci            []byte                 `protobuf:"bytes,3,opt,name=ci,proto3" json:"ci,omitempty"`
	Commitments   [][]byte               `protobuf:"bytes,4,rep,name=commitments,proto3" json:"commitments,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *FrostRound1Cast) Reset() {
	*x = FrostRound1Cast{}
	mi := &file_dkg_dkgpb_v1_frost_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *FrostRound1Cast) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FrostRound1Cast) ProtoMessage() {}

func (x *FrostRound1Cast) ProtoReflect() protoreflect.Message {
	mi := &file_dkg_dkgpb_v1_frost_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FrostRound1Cast.ProtoReflect.Descriptor instead.
func (*FrostRound1Cast) Descriptor() ([]byte, []int) {
	return file_dkg_dkgpb_v1_frost_proto_rawDescGZIP(), []int{2}
}

func (x *FrostRound1Cast) GetKey() *FrostMsgKey {
	if x != nil {
		return x.Key
	}
	return nil
}

func (x *FrostRound1Cast) GetWi() []byte {
	if x != nil {
		return x.Wi
	}
	return nil
}

func (x *FrostRound1Cast) GetCi() []byte {
	if x != nil {
		return x.Ci
	}
	return nil
}

func (x *FrostRound1Cast) GetCommitments() [][]byte {
	if x != nil {
		return x.Commitments
	}
	return nil
}

type FrostRound1P2P struct {
	state         protoimpl.MessageState    `protogen:"open.v1"`
	Shares        []*FrostRound1ShamirShare `protobuf:"bytes,1,rep,name=shares,proto3" json:"shares,omitempty"` // One per validator
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *FrostRound1P2P) Reset() {
	*x = FrostRound1P2P{}
	mi := &file_dkg_dkgpb_v1_frost_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *FrostRound1P2P) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FrostRound1P2P) ProtoMessage() {}

func (x *FrostRound1P2P) ProtoReflect() protoreflect.Message {
	mi := &file_dkg_dkgpb_v1_frost_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FrostRound1P2P.ProtoReflect.Descriptor instead.
func (*FrostRound1P2P) Descriptor() ([]byte, []int) {
	return file_dkg_dkgpb_v1_frost_proto_rawDescGZIP(), []int{3}
}

func (x *FrostRound1P2P) GetShares() []*FrostRound1ShamirShare {
	if x != nil {
		return x.Shares
	}
	return nil
}

type FrostRound1ShamirShare struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Key           *FrostMsgKey           `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Id            uint32                 `protobuf:"varint,2,opt,name=id,proto3" json:"id,omitempty"`
	Value         []byte                 `protobuf:"bytes,3,opt,name=value,proto3" json:"value,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *FrostRound1ShamirShare) Reset() {
	*x = FrostRound1ShamirShare{}
	mi := &file_dkg_dkgpb_v1_frost_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *FrostRound1ShamirShare) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FrostRound1ShamirShare) ProtoMessage() {}

func (x *FrostRound1ShamirShare) ProtoReflect() protoreflect.Message {
	mi := &file_dkg_dkgpb_v1_frost_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FrostRound1ShamirShare.ProtoReflect.Descriptor instead.
func (*FrostRound1ShamirShare) Descriptor() ([]byte, []int) {
	return file_dkg_dkgpb_v1_frost_proto_rawDescGZIP(), []int{4}
}

func (x *FrostRound1ShamirShare) GetKey() *FrostMsgKey {
	if x != nil {
		return x.Key
	}
	return nil
}

func (x *FrostRound1ShamirShare) GetId() uint32 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *FrostRound1ShamirShare) GetValue() []byte {
	if x != nil {
		return x.Value
	}
	return nil
}

type FrostRound2Casts struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Casts         []*FrostRound2Cast     `protobuf:"bytes,1,rep,name=casts,proto3" json:"casts,omitempty"` // One per validator
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *FrostRound2Casts) Reset() {
	*x = FrostRound2Casts{}
	mi := &file_dkg_dkgpb_v1_frost_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *FrostRound2Casts) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FrostRound2Casts) ProtoMessage() {}

func (x *FrostRound2Casts) ProtoReflect() protoreflect.Message {
	mi := &file_dkg_dkgpb_v1_frost_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FrostRound2Casts.ProtoReflect.Descriptor instead.
func (*FrostRound2Casts) Descriptor() ([]byte, []int) {
	return file_dkg_dkgpb_v1_frost_proto_rawDescGZIP(), []int{5}
}

func (x *FrostRound2Casts) GetCasts() []*FrostRound2Cast {
	if x != nil {
		return x.Casts
	}
	return nil
}

type FrostRound2Cast struct {
	state           protoimpl.MessageState `protogen:"open.v1"`
	Key             *FrostMsgKey           `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	VerificationKey []byte                 `protobuf:"bytes,2,opt,name=verification_key,json=verificationKey,proto3" json:"verification_key,omitempty"`
	VkShare         []byte                 `protobuf:"bytes,3,opt,name=vk_share,json=vkShare,proto3" json:"vk_share,omitempty"`
	unknownFields   protoimpl.UnknownFields
	sizeCache       protoimpl.SizeCache
}

func (x *FrostRound2Cast) Reset() {
	*x = FrostRound2Cast{}
	mi := &file_dkg_dkgpb_v1_frost_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *FrostRound2Cast) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FrostRound2Cast) ProtoMessage() {}

func (x *FrostRound2Cast) ProtoReflect() protoreflect.Message {
	mi := &file_dkg_dkgpb_v1_frost_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FrostRound2Cast.ProtoReflect.Descriptor instead.
func (*FrostRound2Cast) Descriptor() ([]byte, []int) {
	return file_dkg_dkgpb_v1_frost_proto_rawDescGZIP(), []int{6}
}

func (x *FrostRound2Cast) GetKey() *FrostMsgKey {
	if x != nil {
		return x.Key
	}
	return nil
}

func (x *FrostRound2Cast) GetVerificationKey() []byte {
	if x != nil {
		return x.VerificationKey
	}
	return nil
}

func (x *FrostRound2Cast) GetVkShare() []byte {
	if x != nil {
		return x.VkShare
	}
	return nil
}

var File_dkg_dkgpb_v1_frost_proto protoreflect.FileDescriptor

const file_dkg_dkgpb_v1_frost_proto_rawDesc = "" +
	"\n" +
	"\x18dkg/dkgpb/v1/frost.proto\x12\fdkg.dkgpb.v1\"`\n" +
	"\vFrostMsgKey\x12\x17\n" +
	"\aval_idx\x18\x01 \x01(\rR\x06valIdx\x12\x1b\n" +
	"\tsource_id\x18\x02 \x01(\rR\bsourceId\x12\x1b\n" +
	"\ttarget_id\x18\x03 \x01(\rR\btargetId\"G\n" +
	"\x10FrostRound1Casts\x123\n" +
	"\x05casts\x18\x01 \x03(\v2\x1d.dkg.dkgpb.v1.FrostRound1CastR\x05casts\"\x80\x01\n" +
	"\x0fFrostRound1Cast\x12+\n" +
	"\x03key\x18\x01 \x01(\v2\x19.dkg.dkgpb.v1.FrostMsgKeyR\x03key\x12\x0e\n" +
	"\x02wi\x18\x02 \x01(\fR\x02wi\x12\x0e\n" +
	"\x02ci\x18\x03 \x01(\fR\x02ci\x12 \n" +
	"\vcommitments\x18\x04 \x03(\fR\vcommitments\"N\n" +
	"\x0eFrostRound1P2P\x12<\n" +
	"\x06shares\x18\x01 \x03(\v2$.dkg.dkgpb.v1.FrostRound1ShamirShareR\x06shares\"k\n" +
	"\x16FrostRound1ShamirShare\x12+\n" +
	"\x03key\x18\x01 \x01(\v2\x19.dkg.dkgpb.v1.FrostMsgKeyR\x03key\x12\x0e\n" +
	"\x02id\x18\x02 \x01(\rR\x02id\x12\x14\n" +
	"\x05value\x18\x03 \x01(\fR\x05value\"G\n" +
	"\x10FrostRound2Casts\x123\n" +
	"\x05casts\x18\x01 \x03(\v2\x1d.dkg.dkgpb.v1.FrostRound2CastR\x05casts\"\x84\x01\n" +
	"\x0fFrostRound2Cast\x12+\n" +
	"\x03key\x18\x01 \x01(\v2\x19.dkg.dkgpb.v1.FrostMsgKeyR\x03key\x12)\n" +
	"\x10verification_key\x18\x02 \x01(\fR\x0fverificationKey\x12\x19\n" +
	"\bvk_share\x18\x03 \x01(\fR\avkShareB,Z*github.com/obolnetwork/charon/dkg/dkgpb/v1b\x06proto3"

var (
	file_dkg_dkgpb_v1_frost_proto_rawDescOnce sync.Once
	file_dkg_dkgpb_v1_frost_proto_rawDescData []byte
)

func file_dkg_dkgpb_v1_frost_proto_rawDescGZIP() []byte {
	file_dkg_dkgpb_v1_frost_proto_rawDescOnce.Do(func() {
		file_dkg_dkgpb_v1_frost_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_dkg_dkgpb_v1_frost_proto_rawDesc), len(file_dkg_dkgpb_v1_frost_proto_rawDesc)))
	})
	return file_dkg_dkgpb_v1_frost_proto_rawDescData
}

var file_dkg_dkgpb_v1_frost_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_dkg_dkgpb_v1_frost_proto_goTypes = []any{
	(*FrostMsgKey)(nil),            // 0: dkg.dkgpb.v1.FrostMsgKey
	(*FrostRound1Casts)(nil),       // 1: dkg.dkgpb.v1.FrostRound1Casts
	(*FrostRound1Cast)(nil),        // 2: dkg.dkgpb.v1.FrostRound1Cast
	(*FrostRound1P2P)(nil),         // 3: dkg.dkgpb.v1.FrostRound1P2P
	(*FrostRound1ShamirShare)(nil), // 4: dkg.dkgpb.v1.FrostRound1ShamirShare
	(*FrostRound2Casts)(nil),       // 5: dkg.dkgpb.v1.FrostRound2Casts
	(*FrostRound2Cast)(nil),        // 6: dkg.dkgpb.v1.FrostRound2Cast
}
var file_dkg_dkgpb_v1_frost_proto_depIdxs = []int32{
	2, // 0: dkg.dkgpb.v1.FrostRound1Casts.casts:type_name -> dkg.dkgpb.v1.FrostRound1Cast
	0, // 1: dkg.dkgpb.v1.FrostRound1Cast.key:type_name -> dkg.dkgpb.v1.FrostMsgKey
	4, // 2: dkg.dkgpb.v1.FrostRound1P2P.shares:type_name -> dkg.dkgpb.v1.FrostRound1ShamirShare
	0, // 3: dkg.dkgpb.v1.FrostRound1ShamirShare.key:type_name -> dkg.dkgpb.v1.FrostMsgKey
	6, // 4: dkg.dkgpb.v1.FrostRound2Casts.casts:type_name -> dkg.dkgpb.v1.FrostRound2Cast
	0, // 5: dkg.dkgpb.v1.FrostRound2Cast.key:type_name -> dkg.dkgpb.v1.FrostMsgKey
	6, // [6:6] is the sub-list for method output_type
	6, // [6:6] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_dkg_dkgpb_v1_frost_proto_init() }
func file_dkg_dkgpb_v1_frost_proto_init() {
	if File_dkg_dkgpb_v1_frost_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_dkg_dkgpb_v1_frost_proto_rawDesc), len(file_dkg_dkgpb_v1_frost_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_dkg_dkgpb_v1_frost_proto_goTypes,
		DependencyIndexes: file_dkg_dkgpb_v1_frost_proto_depIdxs,
		MessageInfos:      file_dkg_dkgpb_v1_frost_proto_msgTypes,
	}.Build()
	File_dkg_dkgpb_v1_frost_proto = out.File
	file_dkg_dkgpb_v1_frost_proto_goTypes = nil
	file_dkg_dkgpb_v1_frost_proto_depIdxs = nil
}
