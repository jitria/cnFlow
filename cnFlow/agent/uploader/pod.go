// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package uploader

import (
    "log"
    "cnFlow/protobuf"
    "cnFlow/types"
)

// RegisterPodToMap stores a pod in the map and sends it to the manager via gRPC stream.
func RegisterPodToMap(podIP string, podInfo types.PodInfo) {
    UploaderH.mu.Lock()
    defer UploaderH.mu.Unlock()

    pbPodInfo := convertTypesToProtobufPod(podInfo)

    UploaderH.PodMap[podIP] = pbPodInfo

    if UploaderH.podStream != nil {
        if err := UploaderH.podStream.Send(pbPodInfo); err != nil {
            log.Printf("[UploaderH] Failed to send pod info: %v", err)
        } else {
            log.Printf("[UploaderH] Sent pod info: %s/%s (IP: %s)", podInfo.Namespace, podInfo.Name, podIP)
        }
    }
}

// UnregisterPodFromMap removes a pod from the map.
func UnregisterPodFromMap(podIP string) {
    UploaderH.mu.Lock()
    defer UploaderH.mu.Unlock()

    if _, exists := UploaderH.PodMap[podIP]; exists {
        delete(UploaderH.PodMap, podIP)
        log.Printf("[UploaderH] Unregistered pod with IP: %s", podIP)
    }
}

// convertTypesToProtobufPod converts a types.PodInfo to its protobuf representation.
func convertTypesToProtobufPod(podInfo types.PodInfo) *protobuf.PodInfo {
    pbNetNsInfo := &protobuf.NetworkNamespaceInfo{
        Name:  podInfo.NetNsInfo.Name,
        Inode: podInfo.NetNsInfo.Inode,
    }

    for _, iface := range podInfo.NetNsInfo.Interfaces {
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

    pbServiceAccount := &protobuf.ServiceAccountInfo{
        Name:                         podInfo.ServiceAccount.Name,
        Namespace:                    podInfo.ServiceAccount.Namespace,
        AutomountServiceAccountToken: podInfo.ServiceAccount.AutomountServiceAccountToken,
        Secrets:                      podInfo.ServiceAccount.Secrets,
        ImagePullSecrets:             podInfo.ServiceAccount.ImagePullSecrets,
    }

    pbSecurityContext := &protobuf.SecurityContextInfo{
        RunAsNonRoot:             podInfo.SecurityContext.RunAsNonRoot,
        Privileged:               podInfo.SecurityContext.Privileged,
        AllowPrivilegeEscalation: podInfo.SecurityContext.AllowPrivilegeEscalation,
        CapabilitiesAdd:          podInfo.SecurityContext.CapabilitiesAdd,
        CapabilitiesDrop:         podInfo.SecurityContext.CapabilitiesDrop,
    }

    if podInfo.SecurityContext.RunAsUser != nil {
        pbSecurityContext.RunAsUser = *podInfo.SecurityContext.RunAsUser
    }
    if podInfo.SecurityContext.RunAsGroup != nil {
        pbSecurityContext.RunAsGroup = *podInfo.SecurityContext.RunAsGroup
    }
    if podInfo.SecurityContext.FSGroup != nil {
        pbSecurityContext.FsGroup = *podInfo.SecurityContext.FSGroup
    }
    pbSecurityContext.SeLinuxOptions = podInfo.SecurityContext.SELinuxOptions

    return &protobuf.PodInfo{
        Name:            podInfo.Name,
        Namespace:       podInfo.Namespace,
        Phase:           podInfo.Phase,
        PodIp:           podInfo.PodIP,
        PodUid:          podInfo.PodUID,
        Node:            podInfo.Node,
        HostIp:          podInfo.HostIP,
        HostNetwork:     podInfo.HostNetwork,
        NetnsInfo:       pbNetNsInfo,
        ServiceAccount:  pbServiceAccount,
        SecurityContext: pbSecurityContext,
    }
}
