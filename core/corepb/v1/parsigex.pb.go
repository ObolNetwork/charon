// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        (unknown)
// source: core/corepb/v1/parsigex.proto

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

type ParSigExMsg struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Duty          *Duty                  `protobuf:"bytes,1,opt,name=duty,proto3" json:"duty,omitempty"`
	DataSet       *ParSignedDataSet      `protobuf:"bytes,2,opt,name=data_set,json=dataSet,proto3" json:"data_set,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ParSigExMsg) Reset() {
	*x = ParSigExMsg{}
	mi := &file_core_corepb_v1_parsigex_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ParSigExMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ParSigExMsg) ProtoMessage() {}

func (x *ParSigExMsg) ProtoReflect() protoreflect.Message {
	mi := &file_core_corepb_v1_parsigex_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ParSigExMsg.ProtoReflect.Descriptor instead.
func (*ParSigExMsg) Descriptor() ([]byte, []int) {
	return file_core_corepb_v1_parsigex_proto_rawDescGZIP(), []int{0}
}

func (x *ParSigExMsg) GetDuty() *Duty {
	if x != nil {
		return x.Duty
	}
	return nil
}

func (x *ParSigExMsg) GetDataSet() *ParSignedDataSet {
	if x != nil {
		return x.DataSet
	}
	return nil
}

var File_core_corepb_v1_parsigex_proto protoreflect.FileDescriptor

const file_core_corepb_v1_parsigex_proto_rawDesc = "" +
	"\n" +
	"\x1dcore/corepb/v1/parsigex.proto\x12\x0ecore.corepb.v1\x1a\x19core/corepb/v1/core.proto\"t\n" +
	"\vParSigExMsg\x12(\n" +
	"\x04duty\x18\x01 \x01(\v2\x14.core.corepb.v1.DutyR\x04duty\x12;\n" +
	"\bdata_set\x18\x02 \x01(\v2 .core.corepb.v1.ParSignedDataSetR\adataSetB.Z,github.com/obolnetwork/charon/core/corepb/v1b\x06proto3"

var (
	file_core_corepb_v1_parsigex_proto_rawDescOnce sync.Once
	file_core_corepb_v1_parsigex_proto_rawDescData []byte
)

func file_core_corepb_v1_parsigex_proto_rawDescGZIP() []byte {
	file_core_corepb_v1_parsigex_proto_rawDescOnce.Do(func() {
		file_core_corepb_v1_parsigex_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_core_corepb_v1_parsigex_proto_rawDesc), len(file_core_corepb_v1_parsigex_proto_rawDesc)))
	})
	return file_core_corepb_v1_parsigex_proto_rawDescData
}

var file_core_corepb_v1_parsigex_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_core_corepb_v1_parsigex_proto_goTypes = []any{
	(*ParSigExMsg)(nil),      // 0: core.corepb.v1.ParSigExMsg
	(*Duty)(nil),             // 1: core.corepb.v1.Duty
	(*ParSignedDataSet)(nil), // 2: core.corepb.v1.ParSignedDataSet
}
var file_core_corepb_v1_parsigex_proto_depIdxs = []int32{
	1, // 0: core.corepb.v1.ParSigExMsg.duty:type_name -> core.corepb.v1.Duty
	2, // 1: core.corepb.v1.ParSigExMsg.data_set:type_name -> core.corepb.v1.ParSignedDataSet
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_core_corepb_v1_parsigex_proto_init() }
func file_core_corepb_v1_parsigex_proto_init() {
	if File_core_corepb_v1_parsigex_proto != nil {
		return
	}
	file_core_corepb_v1_core_proto_init()
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_core_corepb_v1_parsigex_proto_rawDesc), len(file_core_corepb_v1_parsigex_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_core_corepb_v1_parsigex_proto_goTypes,
		DependencyIndexes: file_core_corepb_v1_parsigex_proto_depIdxs,
		MessageInfos:      file_core_corepb_v1_parsigex_proto_msgTypes,
	}.Build()
	File_core_corepb_v1_parsigex_proto = out.File
	file_core_corepb_v1_parsigex_proto_goTypes = nil
	file_core_corepb_v1_parsigex_proto_depIdxs = nil
}
