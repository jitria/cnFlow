// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package attacher

import (
    "fmt"
    "log"

    "github.com/cilium/ebpf"
    "github.com/vishvananda/netlink"
    "golang.org/x/sys/unix"
)

// AddBpfFilter adds a BPF filter to the specified interface.
func AddBpfFilter(iface int, prog *ebpf.Program, prio uint16, name string, direction string) (*netlink.BpfFilter, error) {
    var parent uint32

    switch direction {
    case "ingress":
        parent = netlink.HANDLE_MIN_INGRESS
    case "egress":
        parent = netlink.HANDLE_MIN_EGRESS
    default:
        return nil, fmt.Errorf("invalid direction: %s", direction)
    }

    filter := &netlink.BpfFilter{
        FilterAttrs: netlink.FilterAttrs{
            LinkIndex: iface,
            Parent:    parent,
            Priority:  prio,
            Protocol:  unix.ETH_P_ALL,
        },
        Fd:           prog.FD(),
        Name:         name,
        DirectAction: true,
    }

    if err := netlink.FilterAdd(filter); err != nil {
        return nil, fmt.Errorf("failed to add %s filter: %w", direction, err)
    }

    return filter, nil
}

// DeleteFilter deletes the specified filter from the interface.
func DeleteFilter(f netlink.Filter) error {
    if f == nil {
        log.Println("[Attacher] DeleteFilter called with nil filter")
        return nil
    }

    attrs := f.Attrs()
    linkIndex := attrs.LinkIndex
    parentHandle := attrs.Parent
    filterHandle := attrs.Handle
    filterType := f.Type()

    log.Printf("[Attacher] Deleting %s filter on interface index %d, parent %s, handle %s...",
        filterType, linkIndex, netlink.HandleStr(parentHandle), netlink.HandleStr(filterHandle))

    err := netlink.FilterDel(f)
    if err != nil {
        return fmt.Errorf("failed to delete %s filter on interface index %d, parent %s, handle %s: %w",
            filterType, linkIndex, netlink.HandleStr(parentHandle), netlink.HandleStr(filterHandle), err)
    }

    log.Printf("[Attacher] %s filter on interface index %d, parent %s, handle %s successfully deleted.",
        filterType, linkIndex, netlink.HandleStr(parentHandle), netlink.HandleStr(filterHandle))
    return nil
}
