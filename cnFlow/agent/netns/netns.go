// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package netns

import (
    "fmt"
    "runtime"
    "path/filepath"
    "github.com/vishvananda/netns"
)

var nsDir = "/run/netns"

// SwitchNetworkNamespace switches the current thread to the named network namespace and returns the original handle.
func SwitchNetworkNamespace(nsName string) (netns.NsHandle, error) {
    runtime.LockOSThread()

    curNs, err := netns.Get()
    if err != nil {
        runtime.UnlockOSThread()
        return curNs, fmt.Errorf("failed to get current netns: %v", err)
    }

    nsPath := filepath.Join(nsDir, nsName)

    newNs, err := netns.GetFromPath(nsPath)
    if err != nil {
        curNs.Close()
        runtime.UnlockOSThread()
        return curNs, fmt.Errorf("failed to open netns %s: %v", nsName, err)
    }

    if err := netns.Set(newNs); err != nil {
        curNs.Close()
        newNs.Close()
        runtime.UnlockOSThread()
        return curNs, fmt.Errorf("failed to set netns %s: %v", nsName, err)
    }

    newNs.Close()
    return curNs, nil
}

// RestoreNetNamespace restores the thread to the previously saved network namespace.
func RestoreNetNamespace(curNs netns.NsHandle) {
    if err := netns.Set(curNs); err != nil {
        fmt.Printf("[NetNS] Failed to restore network namespace: %v\n", err)
    }
    curNs.Close()
    runtime.UnlockOSThread()
}