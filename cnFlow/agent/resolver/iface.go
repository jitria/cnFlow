// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package resolver

import (
    "net"
    "strings"
    "cnFlow/types"
)

// getNetworkInterfacesInfo returns information about all network interfaces in the current namespace.
func getNetworkInterfacesInfo() ([]types.NetworkInterfaceInfo, error) {
    interfaces, err := net.Interfaces()
    if err != nil {
        return nil, err
    }

    interfacesInfo := make([]types.NetworkInterfaceInfo, 0, len(interfaces))
    for _, iface := range interfaces {
        ipv4Addrs, ipv6Addrs := getInterfaceAddresses(iface)
        interfacesInfo = append(interfacesInfo, types.NetworkInterfaceInfo{
            Index:      iface.Index,
            MTU:        iface.MTU,
            Name:       iface.Name,
            MACAddress: iface.HardwareAddr.String(),
            IPv4Addrs:  ipv4Addrs,
            IPv6Addrs:  strings.Join(ipv6Addrs, ", "),
        })
    }
    return interfacesInfo, nil
}

// getInterfaceAddresses returns the IPv4 and IPv6 addresses assigned to the given interface.
func getInterfaceAddresses(iface net.Interface) ([]string, []string) {
    var ipv4Addrs, ipv6Addrs []string
    addrs, err := iface.Addrs()
    if err != nil {
        return nil, nil
    }

    for _, addr := range addrs {
        if ipNet, ok := addr.(*net.IPNet); ok {
            if ipNet.IP.To4() != nil {
                ipv4Addrs = append(ipv4Addrs, ipNet.IP.String())
            } else {
                ipv6Addrs = append(ipv6Addrs, ipNet.IP.String())
            }
        }
    }
    return ipv4Addrs, ipv6Addrs
}
