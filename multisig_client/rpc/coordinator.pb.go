// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.5
// 	protoc        v3.6.1
// source: rpc/coordinator.proto

package rpc

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

// Node configuration
type NodeConfig struct {
	state              protoimpl.MessageState `protogen:"open.v1"`
	Name               string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`                             // The name of the node
	RpcAddress         string                 `protobuf:"bytes,2,opt,name=rpcAddress,proto3" json:"rpcAddress,omitempty"`                 // RPC server address (host:port)
	Cert               string                 `protobuf:"bytes,3,opt,name=cert,proto3" json:"cert,omitempty"`                             // Path to the TLS certificate
	Key                string                 `protobuf:"bytes,4,opt,name=key,proto3" json:"key,omitempty"`                               // Path to the TLS private key
	CaCert             string                 `protobuf:"bytes,5,opt,name=caCert,proto3" json:"caCert,omitempty"`                         // Path to the CA certificate
	CoordinatorAddress string                 `protobuf:"bytes,6,opt,name=coordinatorAddress,proto3" json:"coordinatorAddress,omitempty"` // Remote coordinator server address (host:port)
	CoordinatorCaCert  string                 `protobuf:"bytes,7,opt,name=coordinatorCaCert,proto3" json:"coordinatorCaCert,omitempty"`   // Path to the CA certificate for the coordinator
	ClientsCaCert      []string               `protobuf:"bytes,8,rep,name=clientsCaCert,proto3" json:"clientsCaCert,omitempty"`           // List of paths to the Clients CA certificate files
	unknownFields      protoimpl.UnknownFields
	sizeCache          protoimpl.SizeCache
}

func (x *NodeConfig) Reset() {
	*x = NodeConfig{}
	mi := &file_rpc_coordinator_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *NodeConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NodeConfig) ProtoMessage() {}

func (x *NodeConfig) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_coordinator_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NodeConfig.ProtoReflect.Descriptor instead.
func (*NodeConfig) Descriptor() ([]byte, []int) {
	return file_rpc_coordinator_proto_rawDescGZIP(), []int{0}
}

func (x *NodeConfig) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *NodeConfig) GetRpcAddress() string {
	if x != nil {
		return x.RpcAddress
	}
	return ""
}

func (x *NodeConfig) GetCert() string {
	if x != nil {
		return x.Cert
	}
	return ""
}

func (x *NodeConfig) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *NodeConfig) GetCaCert() string {
	if x != nil {
		return x.CaCert
	}
	return ""
}

func (x *NodeConfig) GetCoordinatorAddress() string {
	if x != nil {
		return x.CoordinatorAddress
	}
	return ""
}

func (x *NodeConfig) GetCoordinatorCaCert() string {
	if x != nil {
		return x.CoordinatorCaCert
	}
	return ""
}

func (x *NodeConfig) GetClientsCaCert() []string {
	if x != nil {
		return x.ClientsCaCert
	}
	return nil
}

// Request message for GetConfig RPC
type GetConfigRequest struct {
	state             protoimpl.MessageState `protogen:"open.v1"`
	ParticipantConfig *NodeConfig            `protobuf:"bytes,1,opt,name=participantConfig,proto3" json:"participantConfig,omitempty"`
	unknownFields     protoimpl.UnknownFields
	sizeCache         protoimpl.SizeCache
}

func (x *GetConfigRequest) Reset() {
	*x = GetConfigRequest{}
	mi := &file_rpc_coordinator_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetConfigRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetConfigRequest) ProtoMessage() {}

func (x *GetConfigRequest) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_coordinator_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetConfigRequest.ProtoReflect.Descriptor instead.
func (*GetConfigRequest) Descriptor() ([]byte, []int) {
	return file_rpc_coordinator_proto_rawDescGZIP(), []int{1}
}

func (x *GetConfigRequest) GetParticipantConfig() *NodeConfig {
	if x != nil {
		return x.ParticipantConfig
	}
	return nil
}

// Response message for GetConfig RPC
type GetConfigReply struct {
	state              protoimpl.MessageState `protogen:"open.v1"`
	Success            bool                   `protobuf:"varint,1,opt,name=success,proto3" json:"success,omitempty"`
	Threshold          int32                  `protobuf:"varint,2,opt,name=threshold,proto3" json:"threshold,omitempty"`                                                                                             // Threshold for DKG and multisig
	Leader             string                 `protobuf:"bytes,3,opt,name=leader,proto3" json:"leader,omitempty"`                                                                                                    // Leader name
	ParticipantConfigs map[int32]*NodeConfig  `protobuf:"bytes,4,rep,name=participantConfigs,proto3" json:"participantConfigs,omitempty" protobuf_key:"varint,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"` // Participant configurations
	unknownFields      protoimpl.UnknownFields
	sizeCache          protoimpl.SizeCache
}

func (x *GetConfigReply) Reset() {
	*x = GetConfigReply{}
	mi := &file_rpc_coordinator_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetConfigReply) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetConfigReply) ProtoMessage() {}

func (x *GetConfigReply) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_coordinator_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetConfigReply.ProtoReflect.Descriptor instead.
func (*GetConfigReply) Descriptor() ([]byte, []int) {
	return file_rpc_coordinator_proto_rawDescGZIP(), []int{2}
}

func (x *GetConfigReply) GetSuccess() bool {
	if x != nil {
		return x.Success
	}
	return false
}

func (x *GetConfigReply) GetThreshold() int32 {
	if x != nil {
		return x.Threshold
	}
	return 0
}

func (x *GetConfigReply) GetLeader() string {
	if x != nil {
		return x.Leader
	}
	return ""
}

func (x *GetConfigReply) GetParticipantConfigs() map[int32]*NodeConfig {
	if x != nil {
		return x.ParticipantConfigs
	}
	return nil
}

var File_rpc_coordinator_proto protoreflect.FileDescriptor

var file_rpc_coordinator_proto_rawDesc = string([]byte{
	0x0a, 0x15, 0x72, 0x70, 0x63, 0x2f, 0x63, 0x6f, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x61, 0x74, 0x6f,
	0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x03, 0x72, 0x70, 0x63, 0x22, 0x82, 0x02, 0x0a,
	0x0a, 0x4e, 0x6f, 0x64, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x12, 0x0a, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12,
	0x1e, 0x0a, 0x0a, 0x72, 0x70, 0x63, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0a, 0x72, 0x70, 0x63, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12,
	0x12, 0x0a, 0x04, 0x63, 0x65, 0x72, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x63,
	0x65, 0x72, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x16, 0x0a, 0x06, 0x63, 0x61, 0x43, 0x65, 0x72, 0x74, 0x18,
	0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x63, 0x61, 0x43, 0x65, 0x72, 0x74, 0x12, 0x2e, 0x0a,
	0x12, 0x63, 0x6f, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x61, 0x74, 0x6f, 0x72, 0x41, 0x64, 0x64, 0x72,
	0x65, 0x73, 0x73, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x12, 0x63, 0x6f, 0x6f, 0x72, 0x64,
	0x69, 0x6e, 0x61, 0x74, 0x6f, 0x72, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x2c, 0x0a,
	0x11, 0x63, 0x6f, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x61, 0x74, 0x6f, 0x72, 0x43, 0x61, 0x43, 0x65,
	0x72, 0x74, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x11, 0x63, 0x6f, 0x6f, 0x72, 0x64, 0x69,
	0x6e, 0x61, 0x74, 0x6f, 0x72, 0x43, 0x61, 0x43, 0x65, 0x72, 0x74, 0x12, 0x24, 0x0a, 0x0d, 0x63,
	0x6c, 0x69, 0x65, 0x6e, 0x74, 0x73, 0x43, 0x61, 0x43, 0x65, 0x72, 0x74, 0x18, 0x08, 0x20, 0x03,
	0x28, 0x09, 0x52, 0x0d, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x73, 0x43, 0x61, 0x43, 0x65, 0x72,
	0x74, 0x22, 0x51, 0x0a, 0x10, 0x47, 0x65, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x3d, 0x0a, 0x11, 0x70, 0x61, 0x72, 0x74, 0x69, 0x63, 0x69,
	0x70, 0x61, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x0f, 0x2e, 0x72, 0x70, 0x63, 0x2e, 0x4e, 0x6f, 0x64, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x52, 0x11, 0x70, 0x61, 0x72, 0x74, 0x69, 0x63, 0x69, 0x70, 0x61, 0x6e, 0x74, 0x43, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x22, 0x95, 0x02, 0x0a, 0x0e, 0x47, 0x65, 0x74, 0x43, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x12, 0x18, 0x0a, 0x07, 0x73, 0x75, 0x63, 0x63, 0x65,
	0x73, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73,
	0x73, 0x12, 0x1c, 0x0a, 0x09, 0x74, 0x68, 0x72, 0x65, 0x73, 0x68, 0x6f, 0x6c, 0x64, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x05, 0x52, 0x09, 0x74, 0x68, 0x72, 0x65, 0x73, 0x68, 0x6f, 0x6c, 0x64, 0x12,
	0x16, 0x0a, 0x06, 0x6c, 0x65, 0x61, 0x64, 0x65, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x06, 0x6c, 0x65, 0x61, 0x64, 0x65, 0x72, 0x12, 0x5b, 0x0a, 0x12, 0x70, 0x61, 0x72, 0x74, 0x69,
	0x63, 0x69, 0x70, 0x61, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x73, 0x18, 0x04, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x2b, 0x2e, 0x72, 0x70, 0x63, 0x2e, 0x47, 0x65, 0x74, 0x43, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x2e, 0x50, 0x61, 0x72, 0x74, 0x69, 0x63, 0x69,
	0x70, 0x61, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79,
	0x52, 0x12, 0x70, 0x61, 0x72, 0x74, 0x69, 0x63, 0x69, 0x70, 0x61, 0x6e, 0x74, 0x43, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x73, 0x1a, 0x56, 0x0a, 0x17, 0x50, 0x61, 0x72, 0x74, 0x69, 0x63, 0x69, 0x70,
	0x61, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12,
	0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x03, 0x6b, 0x65,
	0x79, 0x12, 0x25, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x0f, 0x2e, 0x72, 0x70, 0x63, 0x2e, 0x4e, 0x6f, 0x64, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x32, 0x48, 0x0a, 0x0b,
	0x43, 0x6f, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x61, 0x74, 0x6f, 0x72, 0x12, 0x39, 0x0a, 0x09, 0x47,
	0x65, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x15, 0x2e, 0x72, 0x70, 0x63, 0x2e, 0x47,
	0x65, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x13, 0x2e, 0x72, 0x70, 0x63, 0x2e, 0x47, 0x65, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52,
	0x65, 0x70, 0x6c, 0x79, 0x22, 0x00, 0x42, 0x08, 0x5a, 0x06, 0x2e, 0x2e, 0x2f, 0x72, 0x70, 0x63,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
})

var (
	file_rpc_coordinator_proto_rawDescOnce sync.Once
	file_rpc_coordinator_proto_rawDescData []byte
)

func file_rpc_coordinator_proto_rawDescGZIP() []byte {
	file_rpc_coordinator_proto_rawDescOnce.Do(func() {
		file_rpc_coordinator_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_rpc_coordinator_proto_rawDesc), len(file_rpc_coordinator_proto_rawDesc)))
	})
	return file_rpc_coordinator_proto_rawDescData
}

var file_rpc_coordinator_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_rpc_coordinator_proto_goTypes = []any{
	(*NodeConfig)(nil),       // 0: rpc.NodeConfig
	(*GetConfigRequest)(nil), // 1: rpc.GetConfigRequest
	(*GetConfigReply)(nil),   // 2: rpc.GetConfigReply
	nil,                      // 3: rpc.GetConfigReply.ParticipantConfigsEntry
}
var file_rpc_coordinator_proto_depIdxs = []int32{
	0, // 0: rpc.GetConfigRequest.participantConfig:type_name -> rpc.NodeConfig
	3, // 1: rpc.GetConfigReply.participantConfigs:type_name -> rpc.GetConfigReply.ParticipantConfigsEntry
	0, // 2: rpc.GetConfigReply.ParticipantConfigsEntry.value:type_name -> rpc.NodeConfig
	1, // 3: rpc.Coordinator.GetConfig:input_type -> rpc.GetConfigRequest
	2, // 4: rpc.Coordinator.GetConfig:output_type -> rpc.GetConfigReply
	4, // [4:5] is the sub-list for method output_type
	3, // [3:4] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_rpc_coordinator_proto_init() }
func file_rpc_coordinator_proto_init() {
	if File_rpc_coordinator_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_rpc_coordinator_proto_rawDesc), len(file_rpc_coordinator_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_rpc_coordinator_proto_goTypes,
		DependencyIndexes: file_rpc_coordinator_proto_depIdxs,
		MessageInfos:      file_rpc_coordinator_proto_msgTypes,
	}.Build()
	File_rpc_coordinator_proto = out.File
	file_rpc_coordinator_proto_goTypes = nil
	file_rpc_coordinator_proto_depIdxs = nil
}
