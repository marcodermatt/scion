// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v3.21.10
// source: proto/control_plane/experimental/v1/fabrid_extensions.proto

package experimental

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

type FABRIDPolicyType int32

const (
	FABRIDPolicyType_UNSPECIFIED FABRIDPolicyType = 0
	FABRIDPolicyType_LOCAL       FABRIDPolicyType = 1
	FABRIDPolicyType_GLOBAL      FABRIDPolicyType = 2
)

// Enum value maps for FABRIDPolicyType.
var (
	FABRIDPolicyType_name = map[int32]string{
		0: "UNSPECIFIED",
		1: "LOCAL",
		2: "GLOBAL",
	}
	FABRIDPolicyType_value = map[string]int32{
		"UNSPECIFIED": 0,
		"LOCAL":       1,
		"GLOBAL":      2,
	}
)

func (x FABRIDPolicyType) Enum() *FABRIDPolicyType {
	p := new(FABRIDPolicyType)
	*p = x
	return p
}

func (x FABRIDPolicyType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (FABRIDPolicyType) Descriptor() protoreflect.EnumDescriptor {
	return file_proto_control_plane_experimental_v1_fabrid_extensions_proto_enumTypes[0].Descriptor()
}

func (FABRIDPolicyType) Type() protoreflect.EnumType {
	return &file_proto_control_plane_experimental_v1_fabrid_extensions_proto_enumTypes[0]
}

func (x FABRIDPolicyType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use FABRIDPolicyType.Descriptor instead.
func (FABRIDPolicyType) EnumDescriptor() ([]byte, []int) {
	return file_proto_control_plane_experimental_v1_fabrid_extensions_proto_rawDescGZIP(), []int{0}
}

type FABRIDConnectionType int32

const (
	FABRIDConnectionType_UNSPECIFIED_TYPE FABRIDConnectionType = 0
	FABRIDConnectionType_IPv4_RANGE       FABRIDConnectionType = 1
	FABRIDConnectionType_IPv6_RANGE       FABRIDConnectionType = 2
	FABRIDConnectionType_INTERFACE        FABRIDConnectionType = 3
	FABRIDConnectionType_WILDCARD         FABRIDConnectionType = 4
)

// Enum value maps for FABRIDConnectionType.
var (
	FABRIDConnectionType_name = map[int32]string{
		0: "UNSPECIFIED_TYPE",
		1: "IPv4_RANGE",
		2: "IPv6_RANGE",
		3: "INTERFACE",
		4: "WILDCARD",
	}
	FABRIDConnectionType_value = map[string]int32{
		"UNSPECIFIED_TYPE": 0,
		"IPv4_RANGE":       1,
		"IPv6_RANGE":       2,
		"INTERFACE":        3,
		"WILDCARD":         4,
	}
)

func (x FABRIDConnectionType) Enum() *FABRIDConnectionType {
	p := new(FABRIDConnectionType)
	*p = x
	return p
}

func (x FABRIDConnectionType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (FABRIDConnectionType) Descriptor() protoreflect.EnumDescriptor {
	return file_proto_control_plane_experimental_v1_fabrid_extensions_proto_enumTypes[1].Descriptor()
}

func (FABRIDConnectionType) Type() protoreflect.EnumType {
	return &file_proto_control_plane_experimental_v1_fabrid_extensions_proto_enumTypes[1]
}

func (x FABRIDConnectionType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use FABRIDConnectionType.Descriptor instead.
func (FABRIDConnectionType) EnumDescriptor() ([]byte, []int) {
	return file_proto_control_plane_experimental_v1_fabrid_extensions_proto_rawDescGZIP(), []int{1}
}

type FABRIDDetachableMaps struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SupportedIndicesMap []*FABRIDIndexMapEntry             `protobuf:"bytes,1,rep,name=supported_indices_map,json=supportedIndicesMap,proto3" json:"supported_indices_map,omitempty"`
	IndexIdentifierMap  map[uint32]*FABRIDPolicyIdentifier `protobuf:"bytes,2,rep,name=index_identifier_map,json=indexIdentifierMap,proto3" json:"index_identifier_map,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *FABRIDDetachableMaps) Reset() {
	*x = FABRIDDetachableMaps{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_control_plane_experimental_v1_fabrid_extensions_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FABRIDDetachableMaps) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FABRIDDetachableMaps) ProtoMessage() {}

func (x *FABRIDDetachableMaps) ProtoReflect() protoreflect.Message {
	mi := &file_proto_control_plane_experimental_v1_fabrid_extensions_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FABRIDDetachableMaps.ProtoReflect.Descriptor instead.
func (*FABRIDDetachableMaps) Descriptor() ([]byte, []int) {
	return file_proto_control_plane_experimental_v1_fabrid_extensions_proto_rawDescGZIP(), []int{0}
}

func (x *FABRIDDetachableMaps) GetSupportedIndicesMap() []*FABRIDIndexMapEntry {
	if x != nil {
		return x.SupportedIndicesMap
	}
	return nil
}

func (x *FABRIDDetachableMaps) GetIndexIdentifierMap() map[uint32]*FABRIDPolicyIdentifier {
	if x != nil {
		return x.IndexIdentifierMap
	}
	return nil
}

type FABRIDPolicyIdentifier struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PolicyType       FABRIDPolicyType `protobuf:"varint,1,opt,name=policy_type,json=policyType,proto3,enum=proto.control_plane.experimental.v1.FABRIDPolicyType" json:"policy_type,omitempty"`
	PolicyIdentifier uint32           `protobuf:"varint,2,opt,name=policy_identifier,json=policyIdentifier,proto3" json:"policy_identifier,omitempty"`
}

func (x *FABRIDPolicyIdentifier) Reset() {
	*x = FABRIDPolicyIdentifier{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_control_plane_experimental_v1_fabrid_extensions_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FABRIDPolicyIdentifier) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FABRIDPolicyIdentifier) ProtoMessage() {}

func (x *FABRIDPolicyIdentifier) ProtoReflect() protoreflect.Message {
	mi := &file_proto_control_plane_experimental_v1_fabrid_extensions_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FABRIDPolicyIdentifier.ProtoReflect.Descriptor instead.
func (*FABRIDPolicyIdentifier) Descriptor() ([]byte, []int) {
	return file_proto_control_plane_experimental_v1_fabrid_extensions_proto_rawDescGZIP(), []int{1}
}

func (x *FABRIDPolicyIdentifier) GetPolicyType() FABRIDPolicyType {
	if x != nil {
		return x.PolicyType
	}
	return FABRIDPolicyType_UNSPECIFIED
}

func (x *FABRIDPolicyIdentifier) GetPolicyIdentifier() uint32 {
	if x != nil {
		return x.PolicyIdentifier
	}
	return 0
}

type FABRIDIndexMapEntry struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IePair                 *FABRIDIngressEgressPair `protobuf:"bytes,1,opt,name=ie_pair,json=iePair,proto3" json:"ie_pair,omitempty"`
	SupportedPolicyIndices []uint32                 `protobuf:"varint,2,rep,packed,name=supported_policy_indices,json=supportedPolicyIndices,proto3" json:"supported_policy_indices,omitempty"`
}

func (x *FABRIDIndexMapEntry) Reset() {
	*x = FABRIDIndexMapEntry{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_control_plane_experimental_v1_fabrid_extensions_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FABRIDIndexMapEntry) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FABRIDIndexMapEntry) ProtoMessage() {}

func (x *FABRIDIndexMapEntry) ProtoReflect() protoreflect.Message {
	mi := &file_proto_control_plane_experimental_v1_fabrid_extensions_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FABRIDIndexMapEntry.ProtoReflect.Descriptor instead.
func (*FABRIDIndexMapEntry) Descriptor() ([]byte, []int) {
	return file_proto_control_plane_experimental_v1_fabrid_extensions_proto_rawDescGZIP(), []int{2}
}

func (x *FABRIDIndexMapEntry) GetIePair() *FABRIDIngressEgressPair {
	if x != nil {
		return x.IePair
	}
	return nil
}

func (x *FABRIDIndexMapEntry) GetSupportedPolicyIndices() []uint32 {
	if x != nil {
		return x.SupportedPolicyIndices
	}
	return nil
}

type FABRIDIngressEgressPair struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Ingress *FABRIDConnectionPoint `protobuf:"bytes,1,opt,name=ingress,proto3" json:"ingress,omitempty"`
	Egress  *FABRIDConnectionPoint `protobuf:"bytes,2,opt,name=egress,proto3" json:"egress,omitempty"`
}

func (x *FABRIDIngressEgressPair) Reset() {
	*x = FABRIDIngressEgressPair{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_control_plane_experimental_v1_fabrid_extensions_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FABRIDIngressEgressPair) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FABRIDIngressEgressPair) ProtoMessage() {}

func (x *FABRIDIngressEgressPair) ProtoReflect() protoreflect.Message {
	mi := &file_proto_control_plane_experimental_v1_fabrid_extensions_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FABRIDIngressEgressPair.ProtoReflect.Descriptor instead.
func (*FABRIDIngressEgressPair) Descriptor() ([]byte, []int) {
	return file_proto_control_plane_experimental_v1_fabrid_extensions_proto_rawDescGZIP(), []int{3}
}

func (x *FABRIDIngressEgressPair) GetIngress() *FABRIDConnectionPoint {
	if x != nil {
		return x.Ingress
	}
	return nil
}

func (x *FABRIDIngressEgressPair) GetEgress() *FABRIDConnectionPoint {
	if x != nil {
		return x.Egress
	}
	return nil
}

type FABRIDConnectionPoint struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type      FABRIDConnectionType `protobuf:"varint,1,opt,name=type,proto3,enum=proto.control_plane.experimental.v1.FABRIDConnectionType" json:"type,omitempty"`
	IpAddress []byte               `protobuf:"bytes,2,opt,name=ip_address,json=ipAddress,proto3" json:"ip_address,omitempty"`
	IpPrefix  uint32               `protobuf:"varint,3,opt,name=ip_prefix,json=ipPrefix,proto3" json:"ip_prefix,omitempty"`
	Interface uint64               `protobuf:"varint,4,opt,name=interface,proto3" json:"interface,omitempty"`
}

func (x *FABRIDConnectionPoint) Reset() {
	*x = FABRIDConnectionPoint{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_control_plane_experimental_v1_fabrid_extensions_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FABRIDConnectionPoint) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FABRIDConnectionPoint) ProtoMessage() {}

func (x *FABRIDConnectionPoint) ProtoReflect() protoreflect.Message {
	mi := &file_proto_control_plane_experimental_v1_fabrid_extensions_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FABRIDConnectionPoint.ProtoReflect.Descriptor instead.
func (*FABRIDConnectionPoint) Descriptor() ([]byte, []int) {
	return file_proto_control_plane_experimental_v1_fabrid_extensions_proto_rawDescGZIP(), []int{4}
}

func (x *FABRIDConnectionPoint) GetType() FABRIDConnectionType {
	if x != nil {
		return x.Type
	}
	return FABRIDConnectionType_UNSPECIFIED_TYPE
}

func (x *FABRIDConnectionPoint) GetIpAddress() []byte {
	if x != nil {
		return x.IpAddress
	}
	return nil
}

func (x *FABRIDConnectionPoint) GetIpPrefix() uint32 {
	if x != nil {
		return x.IpPrefix
	}
	return 0
}

func (x *FABRIDConnectionPoint) GetInterface() uint64 {
	if x != nil {
		return x.Interface
	}
	return 0
}

var File_proto_control_plane_experimental_v1_fabrid_extensions_proto protoreflect.FileDescriptor

var file_proto_control_plane_experimental_v1_fabrid_extensions_proto_rawDesc = []byte{
	0x0a, 0x3b, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x5f,
	0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x65, 0x78, 0x70, 0x65, 0x72, 0x69, 0x6d, 0x65, 0x6e, 0x74,
	0x61, 0x6c, 0x2f, 0x76, 0x31, 0x2f, 0x66, 0x61, 0x62, 0x72, 0x69, 0x64, 0x5f, 0x65, 0x78, 0x74,
	0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x23, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x5f, 0x70, 0x6c, 0x61,
	0x6e, 0x65, 0x2e, 0x65, 0x78, 0x70, 0x65, 0x72, 0x69, 0x6d, 0x65, 0x6e, 0x74, 0x61, 0x6c, 0x2e,
	0x76, 0x31, 0x22, 0x8f, 0x03, 0x0a, 0x14, 0x46, 0x41, 0x42, 0x52, 0x49, 0x44, 0x44, 0x65, 0x74,
	0x61, 0x63, 0x68, 0x61, 0x62, 0x6c, 0x65, 0x4d, 0x61, 0x70, 0x73, 0x12, 0x6c, 0x0a, 0x15, 0x73,
	0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x5f, 0x69, 0x6e, 0x64, 0x69, 0x63, 0x65, 0x73,
	0x5f, 0x6d, 0x61, 0x70, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x38, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x5f, 0x70, 0x6c, 0x61, 0x6e, 0x65,
	0x2e, 0x65, 0x78, 0x70, 0x65, 0x72, 0x69, 0x6d, 0x65, 0x6e, 0x74, 0x61, 0x6c, 0x2e, 0x76, 0x31,
	0x2e, 0x46, 0x41, 0x42, 0x52, 0x49, 0x44, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x4d, 0x61, 0x70, 0x45,
	0x6e, 0x74, 0x72, 0x79, 0x52, 0x13, 0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x49,
	0x6e, 0x64, 0x69, 0x63, 0x65, 0x73, 0x4d, 0x61, 0x70, 0x12, 0x83, 0x01, 0x0a, 0x14, 0x69, 0x6e,
	0x64, 0x65, 0x78, 0x5f, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x5f, 0x6d,
	0x61, 0x70, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x51, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x5f, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e, 0x65,
	0x78, 0x70, 0x65, 0x72, 0x69, 0x6d, 0x65, 0x6e, 0x74, 0x61, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x46,
	0x41, 0x42, 0x52, 0x49, 0x44, 0x44, 0x65, 0x74, 0x61, 0x63, 0x68, 0x61, 0x62, 0x6c, 0x65, 0x4d,
	0x61, 0x70, 0x73, 0x2e, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66,
	0x69, 0x65, 0x72, 0x4d, 0x61, 0x70, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x12, 0x69, 0x6e, 0x64,
	0x65, 0x78, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x4d, 0x61, 0x70, 0x1a,
	0x82, 0x01, 0x0a, 0x17, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66,
	0x69, 0x65, 0x72, 0x4d, 0x61, 0x70, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b,
	0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x51, 0x0a,
	0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x3b, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x5f, 0x70, 0x6c, 0x61,
	0x6e, 0x65, 0x2e, 0x65, 0x78, 0x70, 0x65, 0x72, 0x69, 0x6d, 0x65, 0x6e, 0x74, 0x61, 0x6c, 0x2e,
	0x76, 0x31, 0x2e, 0x46, 0x41, 0x42, 0x52, 0x49, 0x44, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x49,
	0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x3a, 0x02, 0x38, 0x01, 0x22, 0x9d, 0x01, 0x0a, 0x16, 0x46, 0x41, 0x42, 0x52, 0x49, 0x44, 0x50,
	0x6f, 0x6c, 0x69, 0x63, 0x79, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x12,
	0x56, 0x0a, 0x0b, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0e, 0x32, 0x35, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x63, 0x6f, 0x6e,
	0x74, 0x72, 0x6f, 0x6c, 0x5f, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e, 0x65, 0x78, 0x70, 0x65, 0x72,
	0x69, 0x6d, 0x65, 0x6e, 0x74, 0x61, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x46, 0x41, 0x42, 0x52, 0x49,
	0x44, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x54, 0x79, 0x70, 0x65, 0x52, 0x0a, 0x70, 0x6f, 0x6c,
	0x69, 0x63, 0x79, 0x54, 0x79, 0x70, 0x65, 0x12, 0x2b, 0x0a, 0x11, 0x70, 0x6f, 0x6c, 0x69, 0x63,
	0x79, 0x5f, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x10, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69,
	0x66, 0x69, 0x65, 0x72, 0x22, 0xa6, 0x01, 0x0a, 0x13, 0x46, 0x41, 0x42, 0x52, 0x49, 0x44, 0x49,
	0x6e, 0x64, 0x65, 0x78, 0x4d, 0x61, 0x70, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x55, 0x0a, 0x07,
	0x69, 0x65, 0x5f, 0x70, 0x61, 0x69, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x3c, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x5f, 0x70, 0x6c,
	0x61, 0x6e, 0x65, 0x2e, 0x65, 0x78, 0x70, 0x65, 0x72, 0x69, 0x6d, 0x65, 0x6e, 0x74, 0x61, 0x6c,
	0x2e, 0x76, 0x31, 0x2e, 0x46, 0x41, 0x42, 0x52, 0x49, 0x44, 0x49, 0x6e, 0x67, 0x72, 0x65, 0x73,
	0x73, 0x45, 0x67, 0x72, 0x65, 0x73, 0x73, 0x50, 0x61, 0x69, 0x72, 0x52, 0x06, 0x69, 0x65, 0x50,
	0x61, 0x69, 0x72, 0x12, 0x38, 0x0a, 0x18, 0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64,
	0x5f, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x5f, 0x69, 0x6e, 0x64, 0x69, 0x63, 0x65, 0x73, 0x18,
	0x02, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x16, 0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64,
	0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x49, 0x6e, 0x64, 0x69, 0x63, 0x65, 0x73, 0x22, 0xc3, 0x01,
	0x0a, 0x17, 0x46, 0x41, 0x42, 0x52, 0x49, 0x44, 0x49, 0x6e, 0x67, 0x72, 0x65, 0x73, 0x73, 0x45,
	0x67, 0x72, 0x65, 0x73, 0x73, 0x50, 0x61, 0x69, 0x72, 0x12, 0x54, 0x0a, 0x07, 0x69, 0x6e, 0x67,
	0x72, 0x65, 0x73, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x3a, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x5f, 0x70, 0x6c, 0x61, 0x6e, 0x65,
	0x2e, 0x65, 0x78, 0x70, 0x65, 0x72, 0x69, 0x6d, 0x65, 0x6e, 0x74, 0x61, 0x6c, 0x2e, 0x76, 0x31,
	0x2e, 0x46, 0x41, 0x42, 0x52, 0x49, 0x44, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x52, 0x07, 0x69, 0x6e, 0x67, 0x72, 0x65, 0x73, 0x73, 0x12,
	0x52, 0x0a, 0x06, 0x65, 0x67, 0x72, 0x65, 0x73, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x3a, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x5f,
	0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e, 0x65, 0x78, 0x70, 0x65, 0x72, 0x69, 0x6d, 0x65, 0x6e, 0x74,
	0x61, 0x6c, 0x2e, 0x76, 0x31, 0x2e, 0x46, 0x41, 0x42, 0x52, 0x49, 0x44, 0x43, 0x6f, 0x6e, 0x6e,
	0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x52, 0x06, 0x65, 0x67, 0x72,
	0x65, 0x73, 0x73, 0x22, 0xc0, 0x01, 0x0a, 0x15, 0x46, 0x41, 0x42, 0x52, 0x49, 0x44, 0x43, 0x6f,
	0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x12, 0x4d, 0x0a,
	0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x39, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x5f, 0x70, 0x6c, 0x61, 0x6e,
	0x65, 0x2e, 0x65, 0x78, 0x70, 0x65, 0x72, 0x69, 0x6d, 0x65, 0x6e, 0x74, 0x61, 0x6c, 0x2e, 0x76,
	0x31, 0x2e, 0x46, 0x41, 0x42, 0x52, 0x49, 0x44, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69,
	0x6f, 0x6e, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x1d, 0x0a, 0x0a,
	0x69, 0x70, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x09, 0x69, 0x70, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x1b, 0x0a, 0x09, 0x69,
	0x70, 0x5f, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08,
	0x69, 0x70, 0x50, 0x72, 0x65, 0x66, 0x69, 0x78, 0x12, 0x1c, 0x0a, 0x09, 0x69, 0x6e, 0x74, 0x65,
	0x72, 0x66, 0x61, 0x63, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x04, 0x52, 0x09, 0x69, 0x6e, 0x74,
	0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x2a, 0x3a, 0x0a, 0x10, 0x46, 0x41, 0x42, 0x52, 0x49, 0x44,
	0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x54, 0x79, 0x70, 0x65, 0x12, 0x0f, 0x0a, 0x0b, 0x55, 0x4e,
	0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x09, 0x0a, 0x05, 0x4c,
	0x4f, 0x43, 0x41, 0x4c, 0x10, 0x01, 0x12, 0x0a, 0x0a, 0x06, 0x47, 0x4c, 0x4f, 0x42, 0x41, 0x4c,
	0x10, 0x02, 0x2a, 0x69, 0x0a, 0x14, 0x46, 0x41, 0x42, 0x52, 0x49, 0x44, 0x43, 0x6f, 0x6e, 0x6e,
	0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x54, 0x79, 0x70, 0x65, 0x12, 0x14, 0x0a, 0x10, 0x55, 0x4e,
	0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x10, 0x00,
	0x12, 0x0e, 0x0a, 0x0a, 0x49, 0x50, 0x76, 0x34, 0x5f, 0x52, 0x41, 0x4e, 0x47, 0x45, 0x10, 0x01,
	0x12, 0x0e, 0x0a, 0x0a, 0x49, 0x50, 0x76, 0x36, 0x5f, 0x52, 0x41, 0x4e, 0x47, 0x45, 0x10, 0x02,
	0x12, 0x0d, 0x0a, 0x09, 0x49, 0x4e, 0x54, 0x45, 0x52, 0x46, 0x41, 0x43, 0x45, 0x10, 0x03, 0x12,
	0x0c, 0x0a, 0x08, 0x57, 0x49, 0x4c, 0x44, 0x43, 0x41, 0x52, 0x44, 0x10, 0x04, 0x42, 0x42, 0x5a,
	0x40, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x73, 0x63, 0x69, 0x6f,
	0x6e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x73, 0x63, 0x69, 0x6f, 0x6e, 0x2f, 0x70, 0x6b, 0x67,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x5f, 0x70,
	0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x65, 0x78, 0x70, 0x65, 0x72, 0x69, 0x6d, 0x65, 0x6e, 0x74, 0x61,
	0x6c, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_proto_control_plane_experimental_v1_fabrid_extensions_proto_rawDescOnce sync.Once
	file_proto_control_plane_experimental_v1_fabrid_extensions_proto_rawDescData = file_proto_control_plane_experimental_v1_fabrid_extensions_proto_rawDesc
)

func file_proto_control_plane_experimental_v1_fabrid_extensions_proto_rawDescGZIP() []byte {
	file_proto_control_plane_experimental_v1_fabrid_extensions_proto_rawDescOnce.Do(func() {
		file_proto_control_plane_experimental_v1_fabrid_extensions_proto_rawDescData = protoimpl.X.CompressGZIP(file_proto_control_plane_experimental_v1_fabrid_extensions_proto_rawDescData)
	})
	return file_proto_control_plane_experimental_v1_fabrid_extensions_proto_rawDescData
}

var file_proto_control_plane_experimental_v1_fabrid_extensions_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_proto_control_plane_experimental_v1_fabrid_extensions_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_proto_control_plane_experimental_v1_fabrid_extensions_proto_goTypes = []interface{}{
	(FABRIDPolicyType)(0),           // 0: proto.control_plane.experimental.v1.FABRIDPolicyType
	(FABRIDConnectionType)(0),       // 1: proto.control_plane.experimental.v1.FABRIDConnectionType
	(*FABRIDDetachableMaps)(nil),    // 2: proto.control_plane.experimental.v1.FABRIDDetachableMaps
	(*FABRIDPolicyIdentifier)(nil),  // 3: proto.control_plane.experimental.v1.FABRIDPolicyIdentifier
	(*FABRIDIndexMapEntry)(nil),     // 4: proto.control_plane.experimental.v1.FABRIDIndexMapEntry
	(*FABRIDIngressEgressPair)(nil), // 5: proto.control_plane.experimental.v1.FABRIDIngressEgressPair
	(*FABRIDConnectionPoint)(nil),   // 6: proto.control_plane.experimental.v1.FABRIDConnectionPoint
	nil,                             // 7: proto.control_plane.experimental.v1.FABRIDDetachableMaps.IndexIdentifierMapEntry
}
var file_proto_control_plane_experimental_v1_fabrid_extensions_proto_depIdxs = []int32{
	4, // 0: proto.control_plane.experimental.v1.FABRIDDetachableMaps.supported_indices_map:type_name -> proto.control_plane.experimental.v1.FABRIDIndexMapEntry
	7, // 1: proto.control_plane.experimental.v1.FABRIDDetachableMaps.index_identifier_map:type_name -> proto.control_plane.experimental.v1.FABRIDDetachableMaps.IndexIdentifierMapEntry
	0, // 2: proto.control_plane.experimental.v1.FABRIDPolicyIdentifier.policy_type:type_name -> proto.control_plane.experimental.v1.FABRIDPolicyType
	5, // 3: proto.control_plane.experimental.v1.FABRIDIndexMapEntry.ie_pair:type_name -> proto.control_plane.experimental.v1.FABRIDIngressEgressPair
	6, // 4: proto.control_plane.experimental.v1.FABRIDIngressEgressPair.ingress:type_name -> proto.control_plane.experimental.v1.FABRIDConnectionPoint
	6, // 5: proto.control_plane.experimental.v1.FABRIDIngressEgressPair.egress:type_name -> proto.control_plane.experimental.v1.FABRIDConnectionPoint
	1, // 6: proto.control_plane.experimental.v1.FABRIDConnectionPoint.type:type_name -> proto.control_plane.experimental.v1.FABRIDConnectionType
	3, // 7: proto.control_plane.experimental.v1.FABRIDDetachableMaps.IndexIdentifierMapEntry.value:type_name -> proto.control_plane.experimental.v1.FABRIDPolicyIdentifier
	8, // [8:8] is the sub-list for method output_type
	8, // [8:8] is the sub-list for method input_type
	8, // [8:8] is the sub-list for extension type_name
	8, // [8:8] is the sub-list for extension extendee
	0, // [0:8] is the sub-list for field type_name
}

func init() { file_proto_control_plane_experimental_v1_fabrid_extensions_proto_init() }
func file_proto_control_plane_experimental_v1_fabrid_extensions_proto_init() {
	if File_proto_control_plane_experimental_v1_fabrid_extensions_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_proto_control_plane_experimental_v1_fabrid_extensions_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FABRIDDetachableMaps); i {
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
		file_proto_control_plane_experimental_v1_fabrid_extensions_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FABRIDPolicyIdentifier); i {
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
		file_proto_control_plane_experimental_v1_fabrid_extensions_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FABRIDIndexMapEntry); i {
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
		file_proto_control_plane_experimental_v1_fabrid_extensions_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FABRIDIngressEgressPair); i {
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
		file_proto_control_plane_experimental_v1_fabrid_extensions_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FABRIDConnectionPoint); i {
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
			RawDescriptor: file_proto_control_plane_experimental_v1_fabrid_extensions_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_proto_control_plane_experimental_v1_fabrid_extensions_proto_goTypes,
		DependencyIndexes: file_proto_control_plane_experimental_v1_fabrid_extensions_proto_depIdxs,
		EnumInfos:         file_proto_control_plane_experimental_v1_fabrid_extensions_proto_enumTypes,
		MessageInfos:      file_proto_control_plane_experimental_v1_fabrid_extensions_proto_msgTypes,
	}.Build()
	File_proto_control_plane_experimental_v1_fabrid_extensions_proto = out.File
	file_proto_control_plane_experimental_v1_fabrid_extensions_proto_rawDesc = nil
	file_proto_control_plane_experimental_v1_fabrid_extensions_proto_goTypes = nil
	file_proto_control_plane_experimental_v1_fabrid_extensions_proto_depIdxs = nil
}
