// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package resolver

import (
    "fmt"
    "log"
    "os"
    "path/filepath"
    "syscall"

    "cnFlow/types"
    cnflownetns "cnFlow/agent/netns"
)

var (
    hostNsPath = "/proc/1/ns/net"
    nsDir      = "/run/netns"
    hostNsName = "host"
)

// collectHostNamespaceInfo gathers network namespace info for the host namespace.
func collectHostNamespaceInfo() *types.NetworkNamespaceInfo {
    hostInode, err := getNamespaceInode(hostNsPath)
    if err != nil {
        log.Printf("Failed to get host namespace inode: %v", err)
        return nil
    }

    interfaces, err := getNetworkInterfacesInfo()
    if err != nil {
        log.Printf("Error fetching network interfaces for host: %v", err)
        return nil
    }

    return &types.NetworkNamespaceInfo{
        Name:       hostNsName,
        Inode:      hostInode,
        Interfaces: interfaces,
    }
}

// collectUserNamespaceInfo gathers network namespace info for all user-created namespaces in /run/netns.
func collectUserNamespaceInfo() []types.NetworkNamespaceInfo {
    var nsList []types.NetworkNamespaceInfo

    entries, err := os.ReadDir(nsDir)
    if err != nil {
        log.Printf("Failed to read directory %s: %v", nsDir, err)
        return nil
    }

    for _, entry := range entries {
        if entry.IsDir() {
            continue
        }

        nsPath := filepath.Join(nsDir, entry.Name())
        inode, err := getNamespaceInode(nsPath)
        if err != nil {
            log.Printf("Skipping %s due to error: %v", entry.Name(), err)
            continue
        }

        curNs, err := cnflownetns.SwitchNetworkNamespace(entry.Name())
        if err != nil {
            log.Printf("Skipping namespace %s due to error: %v", entry.Name(), err)
            continue
        }

        interfaces, err := getNetworkInterfacesInfo()
        cnflownetns.RestoreNetNamespace(curNs)
        if err != nil {
            log.Printf("Error fetching network interfaces for %s: %v", entry.Name(), err)
            continue
        }

        nsInfo := types.NetworkNamespaceInfo{
            Name:       entry.Name(),
            Inode:      inode,
            Interfaces: interfaces,
        }

        nsList = append(nsList, nsInfo)
    }

    return nsList
}

// getNamespaceInode returns the inode number of the given namespace file path.
func getNamespaceInode(nsPath string) (uint64, error) {
    fileInfo, err := os.Stat(nsPath)
    if err != nil {
        return 0, fmt.Errorf("failed to stat file %s: %v", nsPath, err)
    }
    stat := fileInfo.Sys().(*syscall.Stat_t)
    return stat.Ino, nil
}
