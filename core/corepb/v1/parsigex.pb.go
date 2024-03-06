// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        (unknown)
// source: core/corepb/v1/parsigex.proto

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

type ParSigExMsg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Duty    *Duty             `protobuf:"bytes,1,opt,name=duty,proto3" json:"duty,omitempty"`
	DataSet *ParSignedDataSet `protobuf:"bytes,2,opt,name=data_set,json=dataSet,proto3" json:"data_set,omitempty"`
}

func (x *ParSigExMsg) Reset() {
	*x = ParSigExMsg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_core_corepb_v1_parsigex_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ParSigExMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ParSigExMsg) ProtoMessage() {}

func (x *ParSigExMsg) ProtoReflect() protoreflect.Message {
	mi := &file_core_corepb_v1_parsigex_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
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

var file_core_corepb_v1_parsigex_proto_rawDesc = []byte{
	0x0a, 0x1d, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2f, 0x76, 0x31,
	0x2f, 0x70, 0x61, 0x72, 0x73, 0x69, 0x67, 0x65, 0x78, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x0e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2e, 0x76, 0x31, 0x1a,
	0x19, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2f, 0x76, 0x31, 0x2f,
	0x63, 0x6f, 0x72, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x74, 0x0a, 0x0b, 0x50, 0x61,
	0x72, 0x53, 0x69, 0x67, 0x45, 0x78, 0x4d, 0x73, 0x67, 0x12, 0x28, 0x0a, 0x04, 0x64, 0x75, 0x74,
	0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63,
	0x6f, 0x72, 0x65, 0x70, 0x62, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x75, 0x74, 0x79, 0x52, 0x04, 0x64,
	0x75, 0x74, 0x79, 0x12, 0x3b, 0x0a, 0x08, 0x64, 0x61, 0x74, 0x61, 0x5f, 0x73, 0x65, 0x74, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x72,
	0x65, 0x70, 0x62, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x61, 0x72, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x64,
	0x44, 0x61, 0x74, 0x61, 0x53, 0x65, 0x74, 0x52, 0x07, 0x64, 0x61, 0x74, 0x61, 0x53, 0x65, 0x74,
	0x42, 0x2e, 0x5a, 0x2c, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f,
	0x62, 0x6f, 0x6c, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2f, 0x63, 0x68, 0x61, 0x72, 0x6f,
	0x6e, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x70, 0x62, 0x2f, 0x76, 0x31,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_core_corepb_v1_parsigex_proto_rawDescOnce sync.Once
	file_core_corepb_v1_parsigex_proto_rawDescData = file_core_corepb_v1_parsigex_proto_rawDesc
)

func file_core_corepb_v1_parsigex_proto_rawDescGZIP() []byte {
	file_core_corepb_v1_parsigex_proto_rawDescOnce.Do(func() {
		file_core_corepb_v1_parsigex_proto_rawDescData = protoimpl.X.CompressGZIP(file_core_corepb_v1_parsigex_proto_rawDescData)
	})
	return file_core_corepb_v1_parsigex_proto_rawDescData
}

var file_core_corepb_v1_parsigex_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_core_corepb_v1_parsigex_proto_goTypes = []interface{}{
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
	if !protoimpl.UnsafeEnabled {
		file_core_corepb_v1_parsigex_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ParSigExMsg); i {
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
			RawDescriptor: file_core_corepb_v1_parsigex_proto_rawDesc,
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
	file_core_corepb_v1_parsigex_proto_rawDesc = nil
	file_core_corepb_v1_parsigex_proto_goTypes = nil
	file_core_corepb_v1_parsigex_proto_depIdxs = nil
}
