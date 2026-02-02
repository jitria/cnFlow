// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package uploader

import (
    "log"
    "cnFlow/protobuf"
    "cnFlow/types"
)

// RegisterNodeToMap stores a node in the map and sends it to the manager via gRPC stream.
func RegisterNodeToMap(hostIP string, nodeInfo types.NodeInfo) {
    UploaderH.mu.Lock()
    defer UploaderH.mu.Unlock()

    pbNodeInfo := convertTypesToProtobufNode(nodeInfo)

    UploaderH.NodeMap[hostIP] = pbNodeInfo

    if UploaderH.nodeStream != nil {
        if err := UploaderH.nodeStream.Send(pbNodeInfo); err != nil {
            log.Printf("[UploaderH] Failed to send node info: %v", err)
        } else {
            log.Printf("[UploaderH] Sent node info: %s (IP: %s)", nodeInfo.Name, hostIP)
        }
    }
}

// UnregisterNodeFromMap removes a node from the map.
func UnregisterNodeFromMap(hostIP string) {
    UploaderH.mu.Lock()
    defer UploaderH.mu.Unlock()

    if _, exists := UploaderH.NodeMap[hostIP]; exists {
        delete(UploaderH.NodeMap, hostIP)
        log.Printf("[UploaderH] Unregistered node with IP: %s", hostIP)
    }
}

// convertTypesToProtobufNode converts a types.NodeInfo to its protobuf representation.
func convertTypesToProtobufNode(nodeInfo types.NodeInfo) *protobuf.NodeInfo {
    pbNetNsInfo := &protobuf.NetworkNamespaceInfo{
        Name:  nodeInfo.NetNsInfo.Name,
        Inode: nodeInfo.NetNsInfo.Inode,
    }

    for _, iface := range nodeInfo.NetNsInfo.Interfaces {
        pbIface := &protobuf.NetworkInterfaceInfo{
            Index:          int32(iface.Index),
            Mtu:            int32(iface.MTU),
            Name:           iface.Name,
            MacAddress:     iface.MACAddress,
            Ipv4Addresses:  iface.IPv4Addrs,
            Ipv6Addresses:  iface.IPv6Addrs,
        }
        pbNetNsInfo.Interfaces = append(pbNetNsInfo.Interfaces, pbIface)
    }

    allocatable := make(map[string]string)
    for k, v := range nodeInfo.Allocatable {
        allocatable[string(k)] = v.String()
    }

    capacity := make(map[string]string)
    for k, v := range nodeInfo.Capacity {
        capacity[string(k)] = v.String()
    }

    pbGeoInfo := &protobuf.GeoInfo{
        Country:   nodeInfo.GeoInfo.Country,
        Region:    nodeInfo.GeoInfo.Region,
        City:      nodeInfo.GeoInfo.City,
        Timezone:  nodeInfo.GeoInfo.Timezone,
        Latitude:  nodeInfo.GeoInfo.Latitude,
        Longitude: nodeInfo.GeoInfo.Longitude,
        Isp:       nodeInfo.GeoInfo.ISP,
        Org:       nodeInfo.GeoInfo.Org,
        AsName:    nodeInfo.GeoInfo.ASName,
        AsNumber:  nodeInfo.GeoInfo.ASNumber,
    }

    return &protobuf.NodeInfo{
        Name:            nodeInfo.Name,
        Uid:             nodeInfo.UID,
        Status:          nodeInfo.Status,
        HostIp:          nodeInfo.HostIP,
        KubeletVersion:  nodeInfo.KubeletVersion,
        OsImage:         nodeInfo.OSImage,
        Allocatable:     allocatable,
        Capacity:        capacity,
        NetnsInfo:       pbNetNsInfo,
        GeoInfo:         pbGeoInfo,
    }
}
