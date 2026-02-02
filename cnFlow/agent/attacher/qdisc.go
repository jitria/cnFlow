// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package attacher

import (
    "fmt"
    "log"

    "github.com/vishvananda/netlink"
)

// EnsureClsactQdiscExists checks and adds a clsact qdisc if it doesn't exist.
func EnsureClsactQdiscExists(ifaceIndex int) (netlink.Qdisc, string, bool, error) {
    link, err := netlink.LinkByIndex(ifaceIndex)
    if err != nil {
        return nil, "", false, fmt.Errorf("failed to get link by index %d: %w", ifaceIndex, err)
    }

    qdiscs, err := netlink.QdiscList(link)
    if err != nil {
        return nil, "", false, fmt.Errorf("failed to list qdiscs: %w", err)
    }

    for _, q := range qdiscs {
        if q.Type() == "clsact" {
            return q, fmt.Sprintf("clsact qdisc already exists on interface index %d", ifaceIndex), false, nil
        }
    }

    qdisc := &netlink.GenericQdisc{
        QdiscAttrs: netlink.QdiscAttrs{
            LinkIndex: ifaceIndex,
            Handle:    netlink.MakeHandle(0xffff, 0),
            Parent:    netlink.HANDLE_CLSACT,
        },
        QdiscType: "clsact",
    }

    if err := netlink.QdiscAdd(qdisc); err != nil {
        // Race condition: another goroutine added the qdisc between our check and add.
        // Re-check and return the existing qdisc.
        qdiscs2, err2 := netlink.QdiscList(link)
        if err2 == nil {
            for _, q := range qdiscs2 {
                if q.Type() == "clsact" {
                    return q, fmt.Sprintf("clsact qdisc already exists on interface index %d (race)", ifaceIndex), false, nil
                }
            }
        }
        return nil, "", false, fmt.Errorf("failed to add clsact qdisc: %w", err)
    }

    return qdisc, fmt.Sprintf("clsact qdisc added to interface index %d", ifaceIndex), true, nil
}

// DeleteQdisc deletes a qdisc from the specified interface.
func DeleteQdisc(q netlink.Qdisc) error {
    if q == nil {
        log.Println("[Attacher] DeleteQdisc called with nil qdisc")
        return nil
    }

    handle := q.Attrs().Handle
    linkIndex := q.Attrs().LinkIndex
    qdiscType := q.Type()

    log.Printf("[Attacher] Deleting %s qdisc on interface index %d with handle %s...", 
        qdiscType, linkIndex, netlink.HandleStr(handle))

    err := netlink.QdiscDel(q)
    if err != nil {
        return fmt.Errorf("failed to delete %s qdisc on interface index %d with handle %s: %w", 
            qdiscType, linkIndex, netlink.HandleStr(handle), err)
    }

    log.Printf("[Attacher] %s qdisc on interface index %d with handle %s successfully deleted.", 
        qdiscType, linkIndex, netlink.HandleStr(handle))
    return nil
}
