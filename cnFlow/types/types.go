// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package types

import (
	v1 "k8s.io/api/core/v1"
)

type NetworkInterfaceInfo struct {
	Index      int      `json:"index"`
	MTU        int      `json:"mtu"`
	Name       string   `json:"name"`
	MACAddress string   `json:"mac_address"`
	IPv4Addrs  []string `json:"ipv4_addresses"`
	IPv6Addrs  string   `json:"ipv6_addresses"`
}

type NetworkNamespaceInfo struct {
	Name       string                 `json:"name"`
	Inode      uint64                 `json:"inode"`
	Interfaces []NetworkInterfaceInfo `json:"interfaces"`
}

type SecurityContextInfo struct {
	RunAsNonRoot            bool     `json:"run_as_non_root"`
	RunAsUser               *int64   `json:"run_as_user,omitempty"`
	RunAsGroup              *int64   `json:"run_as_group,omitempty"`
	FSGroup                 *int64   `json:"fs_group,omitempty"`
	SELinuxOptions          string   `json:"se_linux_options,omitempty"`
	Privileged              bool     `json:"privileged"`
	AllowPrivilegeEscalation bool    `json:"allow_privilege_escalation"`
	CapabilitiesAdd         []string `json:"capabilities_add,omitempty"`
	CapabilitiesDrop        []string `json:"capabilities_drop,omitempty"`
}

type ServiceAccountInfo struct {
	Name                         string   `json:"name"`
	Namespace                    string   `json:"namespace"`
	AutomountServiceAccountToken bool     `json:"automount_service_account_token"`
	Secrets                      []string `json:"secrets,omitempty"`
	ImagePullSecrets             []string `json:"image_pull_secrets,omitempty"`
}

type GeoInfo struct {
	Country   string  `json:"country"`
	Region    string  `json:"region"`
	City      string  `json:"city"`
	Timezone  string  `json:"timezone"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	ISP       string  `json:"isp"`
	Org       string  `json:"org"`
	ASName    string  `json:"as_name"`
	ASNumber  int32   `json:"as_number"`
}

type PodInfo struct {
	Name        string               `json:"name"`
	Namespace   string               `json:"namespace"`
	Phase       string               `json:"phase"`
	PodIP       string               `json:"podIP"`
	PodUID      string               `json:"podUID"`
	Node        string               `json:"node"`
	HostIP      string               `json:"hostIP"`
	HostNetwork bool                 `json:"hostNetwork"`
	NetNsInfo   NetworkNamespaceInfo `json:"networkNamespaceInfo"`

	ServiceAccount ServiceAccountInfo   `json:"service_account"`
	SecurityContext SecurityContextInfo `json:"security_context"`
}

type NodeInfo struct {
	Name           string				`json:"name"`
	UID            string               `json:"uid"`
	Status         string               `json:"status"`
	HostIP         string               `json:"hostIP"`
	KubeletVersion string               `json:"kubeletVersion"`
	OSImage        string               `json:"osImage"`
	Allocatable    v1.ResourceList      `json:"allocatable"`
	Capacity       v1.ResourceList      `json:"capacity"`
	NetNsInfo      NetworkNamespaceInfo `json:"networkNamespacesInfo"`

	GeoInfo        GeoInfo              `json:"geo_info"`
}

type BaseNetworkEvent struct {
	SrcAddr     uint32    `json:"src_addr"`
	DstAddr     uint32    `json:"dst_addr"`
	IPTos       uint32    `json:"ip_tos"`
	IPTotalLen  uint32    `json:"ip_total_len"`
	IPID        uint32    `json:"ip_id"`
	IPFragOff   uint32    `json:"ip_frag_off"`
	IPTtl       uint32    `json:"ip_ttl"`
	IPProtocol  uint32    `json:"ip_protocol"`
	IPCheck     uint32    `json:"ip_check"`
	SrcPort     uint32    `json:"src_port"`
	DstPort     uint32    `json:"dst_port"`
	Seq         uint32    `json:"seq"`
	AckSeq      uint32    `json:"ack_seq"`
	TCPFlags    uint32    `json:"tcp_flags"`
	Window      uint32    `json:"window"`
	TCPCheck    uint32    `json:"tcp_check"`
	UDPLen      uint32    `json:"udp_len"`
	UDPCheck    uint32    `json:"udp_check"`
	TimestampNs uint64    `json:"timestamp_ns"`
	PayloadSize uint32    `json:"payload_size"`
}

type HTTPEvent struct {
	Base         BaseNetworkEvent `json:"base"`
	Method       string          `json:"method"`
	URI          string          `json:"uri"`
	StatusCode   string          `json:"status_code"`
	IsRequest    bool            `json:"is_request"`
}

type HTTP2Event struct {
	Base        BaseNetworkEvent `json:"base"`
	FrameLength uint32          `json:"frame_length"`
	FrameType   uint32          `json:"frame_type"`
	FrameFlags  uint32          `json:"frame_flags"`
	StreamID    uint32          `json:"stream_id"`
	Payload     []byte          `json:"payload"`
}

type DNSEvent struct {
	Base           BaseNetworkEvent `json:"base"`
	TransactionID  uint32          `json:"transaction_id"`
	QueryType      uint32          `json:"query_type"`
	QueryName      string          `json:"query_name"`
	ResponseCode   uint32          `json:"response_code"`
	IsQuery        bool            `json:"is_query"`
}

type RedisEvent struct {
	Base        BaseNetworkEvent `json:"base"`
	CommandType uint32          `json:"command_type"`
	RespType    uint32          `json:"resp_type"`
	Payload     []byte          `json:"payload"`
}

type ICMPEvent struct {
	Base     BaseNetworkEvent `json:"base"`
	Type     uint32          `json:"type"`
	Code     uint32          `json:"code"`
	ID       uint32          `json:"id"`
	Sequence uint32          `json:"sequence"`
}

type KafkaEvent struct {
	Base          BaseNetworkEvent `json:"base"`
	APIKey        uint32          `json:"api_key"`
	APIVersion    uint32          `json:"api_version"`
	CorrelationID uint32          `json:"correlation_id"`
	Payload       []byte          `json:"payload"`
}
