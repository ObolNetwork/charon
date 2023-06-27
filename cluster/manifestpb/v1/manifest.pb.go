// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        (unknown)
// source: cluster/manifestpb/v1/manifest.proto

package v1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	anypb "google.golang.org/protobuf/types/known/anypb"
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

// Cluster represents the manifest of a cluster after applying a sequence of mutations.
type Cluster struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	InitialMutationHash []byte       `protobuf:"bytes,1,opt,name=initial_mutation_hash,json=initialMutationHash,proto3" json:"initial_mutation_hash,omitempty"` // InitialMutationHash is the hash of first signed mutation, uniquely identifying cluster, aka "cluster hash". It must be 32 bytes.
	LatestMutationHash  []byte       `protobuf:"bytes,2,opt,name=latest_mutation_hash,json=latestMutationHash,proto3" json:"latest_mutation_hash,omitempty"`    // LatestMutationHash is the hash of last signed mutation, identifying this specific cluster iteration. It must be 32 bytes.
	Name                string       `protobuf:"bytes,3,opt,name=name,proto3" json:"name,omitempty"`                                                            // Name is the name of the cluster.
	Threshold           int32        `protobuf:"varint,4,opt,name=threshold,proto3" json:"threshold,omitempty"`                                                 // Threshold is the threshold of the cluster.
	DkgAlgorithm        string       `protobuf:"bytes,5,opt,name=dkg_algorithm,json=dkgAlgorithm,proto3" json:"dkg_algorithm,omitempty"`                        // DKGAlgorithm is the DKG algorithm used to create the validator keys of the cluster.
	ForkVersion         []byte       `protobuf:"bytes,6,opt,name=fork_version,json=forkVersion,proto3" json:"fork_version,omitempty"`                           // ForkVersion is the fork version (network/chain) of the cluster. It must be 4 bytes.
	Operators           []*Operator  `protobuf:"bytes,7,rep,name=operators,proto3" json:"operators,omitempty"`                                                  // Operators is the list of operators of the cluster.
	Validators          []*Validator `protobuf:"bytes,8,rep,name=validators,proto3" json:"validators,omitempty"`                                                // Validators is the list of validators of the cluster.
}

func (x *Cluster) Reset() {
	*x = Cluster{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cluster_manifestpb_v1_manifest_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Cluster) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Cluster) ProtoMessage() {}

func (x *Cluster) ProtoReflect() protoreflect.Message {
	mi := &file_cluster_manifestpb_v1_manifest_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Cluster.ProtoReflect.Descriptor instead.
func (*Cluster) Descriptor() ([]byte, []int) {
	return file_cluster_manifestpb_v1_manifest_proto_rawDescGZIP(), []int{0}
}

func (x *Cluster) GetInitialMutationHash() []byte {
	if x != nil {
		return x.InitialMutationHash
	}
	return nil
}

func (x *Cluster) GetLatestMutationHash() []byte {
	if x != nil {
		return x.LatestMutationHash
	}
	return nil
}

func (x *Cluster) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Cluster) GetThreshold() int32 {
	if x != nil {
		return x.Threshold
	}
	return 0
}

func (x *Cluster) GetDkgAlgorithm() string {
	if x != nil {
		return x.DkgAlgorithm
	}
	return ""
}

func (x *Cluster) GetForkVersion() []byte {
	if x != nil {
		return x.ForkVersion
	}
	return nil
}

func (x *Cluster) GetOperators() []*Operator {
	if x != nil {
		return x.Operators
	}
	return nil
}

func (x *Cluster) GetValidators() []*Validator {
	if x != nil {
		return x.Validators
	}
	return nil
}

// Mutation mutates the cluster manifest.
type Mutation struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Parent    []byte                 `protobuf:"bytes,1,opt,name=parent,proto3" json:"parent,omitempty"`       // Parent is the hash of the parent mutation. It must be 32 bytes.
	Type      string                 `protobuf:"bytes,2,opt,name=type,proto3" json:"type,omitempty"`           // Type is the type of mutation.
	Timestamp *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=timestamp,proto3" json:"timestamp,omitempty"` // Timestamp is the time of the mutation.
	Data      *anypb.Any             `protobuf:"bytes,4,opt,name=data,proto3" json:"data,omitempty"`           // Data is the data of the mutation. Must be non-nil.
}

func (x *Mutation) Reset() {
	*x = Mutation{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cluster_manifestpb_v1_manifest_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Mutation) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Mutation) ProtoMessage() {}

func (x *Mutation) ProtoReflect() protoreflect.Message {
	mi := &file_cluster_manifestpb_v1_manifest_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Mutation.ProtoReflect.Descriptor instead.
func (*Mutation) Descriptor() ([]byte, []int) {
	return file_cluster_manifestpb_v1_manifest_proto_rawDescGZIP(), []int{1}
}

func (x *Mutation) GetParent() []byte {
	if x != nil {
		return x.Parent
	}
	return nil
}

func (x *Mutation) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *Mutation) GetTimestamp() *timestamppb.Timestamp {
	if x != nil {
		return x.Timestamp
	}
	return nil
}

func (x *Mutation) GetData() *anypb.Any {
	if x != nil {
		return x.Data
	}
	return nil
}

// SignedMutation is a mutation signed by a signer.
type SignedMutation struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Mutation  *Mutation `protobuf:"bytes,1,opt,name=mutation,proto3" json:"mutation,omitempty"`   // Mutation is the mutation.
	Signer    []byte    `protobuf:"bytes,2,opt,name=signer,proto3" json:"signer,omitempty"`       // Signer is the identity (public key) of the signer.
	Signature []byte    `protobuf:"bytes,3,opt,name=signature,proto3" json:"signature,omitempty"` // Signature is the signature of the mutation.
}

func (x *SignedMutation) Reset() {
	*x = SignedMutation{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cluster_manifestpb_v1_manifest_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignedMutation) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignedMutation) ProtoMessage() {}

func (x *SignedMutation) ProtoReflect() protoreflect.Message {
	mi := &file_cluster_manifestpb_v1_manifest_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignedMutation.ProtoReflect.Descriptor instead.
func (*SignedMutation) Descriptor() ([]byte, []int) {
	return file_cluster_manifestpb_v1_manifest_proto_rawDescGZIP(), []int{2}
}

func (x *SignedMutation) GetMutation() *Mutation {
	if x != nil {
		return x.Mutation
	}
	return nil
}

func (x *SignedMutation) GetSigner() []byte {
	if x != nil {
		return x.Signer
	}
	return nil
}

func (x *SignedMutation) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

// SignedMutationList is a list of signed mutations.
type SignedMutationList struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Mutations []*SignedMutation `protobuf:"bytes,1,rep,name=mutations,proto3" json:"mutations,omitempty"` // Mutations is the list of mutations.
}

func (x *SignedMutationList) Reset() {
	*x = SignedMutationList{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cluster_manifestpb_v1_manifest_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignedMutationList) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignedMutationList) ProtoMessage() {}

func (x *SignedMutationList) ProtoReflect() protoreflect.Message {
	mi := &file_cluster_manifestpb_v1_manifest_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignedMutationList.ProtoReflect.Descriptor instead.
func (*SignedMutationList) Descriptor() ([]byte, []int) {
	return file_cluster_manifestpb_v1_manifest_proto_rawDescGZIP(), []int{3}
}

func (x *SignedMutationList) GetMutations() []*SignedMutation {
	if x != nil {
		return x.Mutations
	}
	return nil
}

// Operator represents the operator of a node in the cluster.
type Operator struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Address string `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"` // Address is the operator's Ethereum address.
	Enr     string `protobuf:"bytes,2,opt,name=enr,proto3" json:"enr,omitempty"`         // enr identifies the operator's charon node.
}

func (x *Operator) Reset() {
	*x = Operator{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cluster_manifestpb_v1_manifest_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Operator) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Operator) ProtoMessage() {}

func (x *Operator) ProtoReflect() protoreflect.Message {
	mi := &file_cluster_manifestpb_v1_manifest_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Operator.ProtoReflect.Descriptor instead.
func (*Operator) Descriptor() ([]byte, []int) {
	return file_cluster_manifestpb_v1_manifest_proto_rawDescGZIP(), []int{4}
}

func (x *Operator) GetAddress() string {
	if x != nil {
		return x.Address
	}
	return ""
}

func (x *Operator) GetEnr() string {
	if x != nil {
		return x.Enr
	}
	return ""
}

// Validator represents a distributed validator managed by the DV cluster.
type Validator struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PublicKey               []byte   `protobuf:"bytes,1,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`                                             // PublicKey is the group public key of the validator.
	PubShares               [][]byte `protobuf:"bytes,2,rep,name=pub_shares,json=pubShares,proto3" json:"pub_shares,omitempty"`                                             // PubShares is the ordered list of public shares of the validator.
	FeeRecipientAddress     string   `protobuf:"bytes,3,opt,name=fee_recipient_address,json=feeRecipientAddress,proto3" json:"fee_recipient_address,omitempty"`             // FeeRecipientAddress is the fee recipient Ethereum address of the validator.
	WithdrawalAddress       string   `protobuf:"bytes,4,opt,name=withdrawal_address,json=withdrawalAddress,proto3" json:"withdrawal_address,omitempty"`                     // WithdrawalAddress is the withdrawal Ethereum address of the validator.
	BuilderRegistrationJson []byte   `protobuf:"bytes,5,opt,name=builder_registration_json,json=builderRegistrationJson,proto3" json:"builder_registration_json,omitempty"` // BuilderRegistration is the pre-generated json-formatted builder-API validator registration of the validator.
}

func (x *Validator) Reset() {
	*x = Validator{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cluster_manifestpb_v1_manifest_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Validator) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Validator) ProtoMessage() {}

func (x *Validator) ProtoReflect() protoreflect.Message {
	mi := &file_cluster_manifestpb_v1_manifest_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Validator.ProtoReflect.Descriptor instead.
func (*Validator) Descriptor() ([]byte, []int) {
	return file_cluster_manifestpb_v1_manifest_proto_rawDescGZIP(), []int{5}
}

func (x *Validator) GetPublicKey() []byte {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

func (x *Validator) GetPubShares() [][]byte {
	if x != nil {
		return x.PubShares
	}
	return nil
}

func (x *Validator) GetFeeRecipientAddress() string {
	if x != nil {
		return x.FeeRecipientAddress
	}
	return ""
}

func (x *Validator) GetWithdrawalAddress() string {
	if x != nil {
		return x.WithdrawalAddress
	}
	return ""
}

func (x *Validator) GetBuilderRegistrationJson() []byte {
	if x != nil {
		return x.BuilderRegistrationJson
	}
	return nil
}

// ValidatorList is a list of validators.
type ValidatorList struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Validators []*Validator `protobuf:"bytes,1,rep,name=validators,proto3" json:"validators,omitempty"` // Validators is the list of validators.
}

func (x *ValidatorList) Reset() {
	*x = ValidatorList{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cluster_manifestpb_v1_manifest_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ValidatorList) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ValidatorList) ProtoMessage() {}

func (x *ValidatorList) ProtoReflect() protoreflect.Message {
	mi := &file_cluster_manifestpb_v1_manifest_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ValidatorList.ProtoReflect.Descriptor instead.
func (*ValidatorList) Descriptor() ([]byte, []int) {
	return file_cluster_manifestpb_v1_manifest_proto_rawDescGZIP(), []int{6}
}

func (x *ValidatorList) GetValidators() []*Validator {
	if x != nil {
		return x.Validators
	}
	return nil
}

// LegacyLock represents a json formatted legacy cluster lock file.
type LegacyLock struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Json []byte `protobuf:"bytes,1,opt,name=json,proto3" json:"json,omitempty"`
}

func (x *LegacyLock) Reset() {
	*x = LegacyLock{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cluster_manifestpb_v1_manifest_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LegacyLock) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LegacyLock) ProtoMessage() {}

func (x *LegacyLock) ProtoReflect() protoreflect.Message {
	mi := &file_cluster_manifestpb_v1_manifest_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LegacyLock.ProtoReflect.Descriptor instead.
func (*LegacyLock) Descriptor() ([]byte, []int) {
	return file_cluster_manifestpb_v1_manifest_proto_rawDescGZIP(), []int{7}
}

func (x *LegacyLock) GetJson() []byte {
	if x != nil {
		return x.Json
	}
	return nil
}

// Empty is an empty/noop message.
type Empty struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *Empty) Reset() {
	*x = Empty{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cluster_manifestpb_v1_manifest_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Empty) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Empty) ProtoMessage() {}

func (x *Empty) ProtoReflect() protoreflect.Message {
	mi := &file_cluster_manifestpb_v1_manifest_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Empty.ProtoReflect.Descriptor instead.
func (*Empty) Descriptor() ([]byte, []int) {
	return file_cluster_manifestpb_v1_manifest_proto_rawDescGZIP(), []int{8}
}

var File_cluster_manifestpb_v1_manifest_proto protoreflect.FileDescriptor

var file_cluster_manifestpb_v1_manifest_proto_rawDesc = []byte{
	0x0a, 0x24, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x2f, 0x6d, 0x61, 0x6e, 0x69, 0x66, 0x65,
	0x73, 0x74, 0x70, 0x62, 0x2f, 0x76, 0x31, 0x2f, 0x6d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x15, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x2e,
	0x6d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, 0x70, 0x62, 0x2e, 0x76, 0x31, 0x1a, 0x1f, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74,
	0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x19,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f,
	0x61, 0x6e, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xea, 0x02, 0x0a, 0x07, 0x43, 0x6c,
	0x75, 0x73, 0x74, 0x65, 0x72, 0x12, 0x32, 0x0a, 0x15, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x6c,
	0x5f, 0x6d, 0x75, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x68, 0x61, 0x73, 0x68, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x13, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x6c, 0x4d, 0x75, 0x74,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x48, 0x61, 0x73, 0x68, 0x12, 0x30, 0x0a, 0x14, 0x6c, 0x61, 0x74,
	0x65, 0x73, 0x74, 0x5f, 0x6d, 0x75, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x68, 0x61, 0x73,
	0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x12, 0x6c, 0x61, 0x74, 0x65, 0x73, 0x74, 0x4d,
	0x75, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x48, 0x61, 0x73, 0x68, 0x12, 0x12, 0x0a, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12,
	0x1c, 0x0a, 0x09, 0x74, 0x68, 0x72, 0x65, 0x73, 0x68, 0x6f, 0x6c, 0x64, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x05, 0x52, 0x09, 0x74, 0x68, 0x72, 0x65, 0x73, 0x68, 0x6f, 0x6c, 0x64, 0x12, 0x23, 0x0a,
	0x0d, 0x64, 0x6b, 0x67, 0x5f, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x18, 0x05,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x64, 0x6b, 0x67, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74,
	0x68, 0x6d, 0x12, 0x21, 0x0a, 0x0c, 0x66, 0x6f, 0x72, 0x6b, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x66, 0x6f, 0x72, 0x6b, 0x56, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x3d, 0x0a, 0x09, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x6f,
	0x72, 0x73, 0x18, 0x07, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x63, 0x6c, 0x75, 0x73, 0x74,
	0x65, 0x72, 0x2e, 0x6d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, 0x70, 0x62, 0x2e, 0x76, 0x31,
	0x2e, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x52, 0x09, 0x6f, 0x70, 0x65, 0x72, 0x61,
	0x74, 0x6f, 0x72, 0x73, 0x12, 0x40, 0x0a, 0x0a, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f,
	0x72, 0x73, 0x18, 0x08, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x63, 0x6c, 0x75, 0x73, 0x74,
	0x65, 0x72, 0x2e, 0x6d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, 0x70, 0x62, 0x2e, 0x76, 0x31,
	0x2e, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x52, 0x0a, 0x76, 0x61, 0x6c, 0x69,
	0x64, 0x61, 0x74, 0x6f, 0x72, 0x73, 0x22, 0x9a, 0x01, 0x0a, 0x08, 0x4d, 0x75, 0x74, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x12, 0x16, 0x0a, 0x06, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x06, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x74,
	0x79, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12,
	0x38, 0x0a, 0x09, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09,
	0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x12, 0x28, 0x0a, 0x04, 0x64, 0x61, 0x74,
	0x61, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x41, 0x6e, 0x79, 0x52, 0x04, 0x64,
	0x61, 0x74, 0x61, 0x22, 0x83, 0x01, 0x0a, 0x0e, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x4d, 0x75,
	0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x3b, 0x0a, 0x08, 0x6d, 0x75, 0x74, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x63, 0x6c, 0x75, 0x73, 0x74,
	0x65, 0x72, 0x2e, 0x6d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, 0x70, 0x62, 0x2e, 0x76, 0x31,
	0x2e, 0x4d, 0x75, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x08, 0x6d, 0x75, 0x74, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x72, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x06, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x72, 0x12, 0x1c, 0x0a, 0x09, 0x73,
	0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09,
	0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x22, 0x59, 0x0a, 0x12, 0x53, 0x69, 0x67,
	0x6e, 0x65, 0x64, 0x4d, 0x75, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4c, 0x69, 0x73, 0x74, 0x12,
	0x43, 0x0a, 0x09, 0x6d, 0x75, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x01, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x25, 0x2e, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x2e, 0x6d, 0x61, 0x6e,
	0x69, 0x66, 0x65, 0x73, 0x74, 0x70, 0x62, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x65,
	0x64, 0x4d, 0x75, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x09, 0x6d, 0x75, 0x74, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x73, 0x22, 0x36, 0x0a, 0x08, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72,
	0x12, 0x18, 0x0a, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x10, 0x0a, 0x03, 0x65, 0x6e,
	0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x65, 0x6e, 0x72, 0x22, 0xe8, 0x01, 0x0a,
	0x09, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x75,
	0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09,
	0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x75, 0x62,
	0x5f, 0x73, 0x68, 0x61, 0x72, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x09, 0x70,
	0x75, 0x62, 0x53, 0x68, 0x61, 0x72, 0x65, 0x73, 0x12, 0x32, 0x0a, 0x15, 0x66, 0x65, 0x65, 0x5f,
	0x72, 0x65, 0x63, 0x69, 0x70, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73,
	0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x13, 0x66, 0x65, 0x65, 0x52, 0x65, 0x63, 0x69,
	0x70, 0x69, 0x65, 0x6e, 0x74, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x2d, 0x0a, 0x12,
	0x77, 0x69, 0x74, 0x68, 0x64, 0x72, 0x61, 0x77, 0x61, 0x6c, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65,
	0x73, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x11, 0x77, 0x69, 0x74, 0x68, 0x64, 0x72,
	0x61, 0x77, 0x61, 0x6c, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x3a, 0x0a, 0x19, 0x62,
	0x75, 0x69, 0x6c, 0x64, 0x65, 0x72, 0x5f, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x5f, 0x6a, 0x73, 0x6f, 0x6e, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x17,
	0x62, 0x75, 0x69, 0x6c, 0x64, 0x65, 0x72, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x4a, 0x73, 0x6f, 0x6e, 0x22, 0x51, 0x0a, 0x0d, 0x56, 0x61, 0x6c, 0x69, 0x64,
	0x61, 0x74, 0x6f, 0x72, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x40, 0x0a, 0x0a, 0x76, 0x61, 0x6c, 0x69,
	0x64, 0x61, 0x74, 0x6f, 0x72, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x63,
	0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x2e, 0x6d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, 0x70,
	0x62, 0x2e, 0x76, 0x31, 0x2e, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x52, 0x0a,
	0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x73, 0x22, 0x20, 0x0a, 0x0a, 0x4c, 0x65,
	0x67, 0x61, 0x63, 0x79, 0x4c, 0x6f, 0x63, 0x6b, 0x12, 0x12, 0x0a, 0x04, 0x6a, 0x73, 0x6f, 0x6e,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x6a, 0x73, 0x6f, 0x6e, 0x22, 0x07, 0x0a, 0x05,
	0x45, 0x6d, 0x70, 0x74, 0x79, 0x42, 0x35, 0x5a, 0x33, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e,
	0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x62, 0x6f, 0x6c, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2f,
	0x63, 0x68, 0x61, 0x72, 0x6f, 0x6e, 0x2f, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x2f, 0x6d,
	0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, 0x70, 0x62, 0x2f, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_cluster_manifestpb_v1_manifest_proto_rawDescOnce sync.Once
	file_cluster_manifestpb_v1_manifest_proto_rawDescData = file_cluster_manifestpb_v1_manifest_proto_rawDesc
)

func file_cluster_manifestpb_v1_manifest_proto_rawDescGZIP() []byte {
	file_cluster_manifestpb_v1_manifest_proto_rawDescOnce.Do(func() {
		file_cluster_manifestpb_v1_manifest_proto_rawDescData = protoimpl.X.CompressGZIP(file_cluster_manifestpb_v1_manifest_proto_rawDescData)
	})
	return file_cluster_manifestpb_v1_manifest_proto_rawDescData
}

var file_cluster_manifestpb_v1_manifest_proto_msgTypes = make([]protoimpl.MessageInfo, 9)
var file_cluster_manifestpb_v1_manifest_proto_goTypes = []interface{}{
	(*Cluster)(nil),               // 0: cluster.manifestpb.v1.Cluster
	(*Mutation)(nil),              // 1: cluster.manifestpb.v1.Mutation
	(*SignedMutation)(nil),        // 2: cluster.manifestpb.v1.SignedMutation
	(*SignedMutationList)(nil),    // 3: cluster.manifestpb.v1.SignedMutationList
	(*Operator)(nil),              // 4: cluster.manifestpb.v1.Operator
	(*Validator)(nil),             // 5: cluster.manifestpb.v1.Validator
	(*ValidatorList)(nil),         // 6: cluster.manifestpb.v1.ValidatorList
	(*LegacyLock)(nil),            // 7: cluster.manifestpb.v1.LegacyLock
	(*Empty)(nil),                 // 8: cluster.manifestpb.v1.Empty
	(*timestamppb.Timestamp)(nil), // 9: google.protobuf.Timestamp
	(*anypb.Any)(nil),             // 10: google.protobuf.Any
}
var file_cluster_manifestpb_v1_manifest_proto_depIdxs = []int32{
	4,  // 0: cluster.manifestpb.v1.Cluster.operators:type_name -> cluster.manifestpb.v1.Operator
	5,  // 1: cluster.manifestpb.v1.Cluster.validators:type_name -> cluster.manifestpb.v1.Validator
	9,  // 2: cluster.manifestpb.v1.Mutation.timestamp:type_name -> google.protobuf.Timestamp
	10, // 3: cluster.manifestpb.v1.Mutation.data:type_name -> google.protobuf.Any
	1,  // 4: cluster.manifestpb.v1.SignedMutation.mutation:type_name -> cluster.manifestpb.v1.Mutation
	2,  // 5: cluster.manifestpb.v1.SignedMutationList.mutations:type_name -> cluster.manifestpb.v1.SignedMutation
	5,  // 6: cluster.manifestpb.v1.ValidatorList.validators:type_name -> cluster.manifestpb.v1.Validator
	7,  // [7:7] is the sub-list for method output_type
	7,  // [7:7] is the sub-list for method input_type
	7,  // [7:7] is the sub-list for extension type_name
	7,  // [7:7] is the sub-list for extension extendee
	0,  // [0:7] is the sub-list for field type_name
}

func init() { file_cluster_manifestpb_v1_manifest_proto_init() }
func file_cluster_manifestpb_v1_manifest_proto_init() {
	if File_cluster_manifestpb_v1_manifest_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_cluster_manifestpb_v1_manifest_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Cluster); i {
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
		file_cluster_manifestpb_v1_manifest_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Mutation); i {
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
		file_cluster_manifestpb_v1_manifest_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignedMutation); i {
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
		file_cluster_manifestpb_v1_manifest_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignedMutationList); i {
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
		file_cluster_manifestpb_v1_manifest_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Operator); i {
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
		file_cluster_manifestpb_v1_manifest_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Validator); i {
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
		file_cluster_manifestpb_v1_manifest_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ValidatorList); i {
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
		file_cluster_manifestpb_v1_manifest_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LegacyLock); i {
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
		file_cluster_manifestpb_v1_manifest_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Empty); i {
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
			RawDescriptor: file_cluster_manifestpb_v1_manifest_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   9,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_cluster_manifestpb_v1_manifest_proto_goTypes,
		DependencyIndexes: file_cluster_manifestpb_v1_manifest_proto_depIdxs,
		MessageInfos:      file_cluster_manifestpb_v1_manifest_proto_msgTypes,
	}.Build()
	File_cluster_manifestpb_v1_manifest_proto = out.File
	file_cluster_manifestpb_v1_manifest_proto_rawDesc = nil
	file_cluster_manifestpb_v1_manifest_proto_goTypes = nil
	file_cluster_manifestpb_v1_manifest_proto_depIdxs = nil
}
