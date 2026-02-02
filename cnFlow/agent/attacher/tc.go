// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package attacher

import (
    "fmt"
    "log"

    "cnFlow/types"
    cnflownetns "cnFlow/agent/netns"

    "github.com/vishvananda/netns"
)

// SetupTC loads eBPF programs and attaches ingress/egress TC filters to the given interface.
func SetupTC(nsName string, iface types.NetworkInterfaceInfo, name string) (*BPFContext, error) {
    log.Printf("[Attacher] Setting up TC for interface %s in namespace %s for %s", iface.Name, nsName, name)

    var curNs netns.NsHandle
    var err error

    if nsName != "host" {
        curNs, err = cnflownetns.SwitchNetworkNamespace(nsName)
        if err != nil {
            log.Printf("[Attacher] Failed to switch to network namespace %s: %v", nsName, err)
            return nil, err
        }
        defer cnflownetns.RestoreNetNamespace(curNs)
        log.Printf("[Attacher] Switched to network namespace: %s", nsName)
    }

    qdisc, msg, created, err := EnsureClsactQdiscExists(iface.Index)
    if err != nil {
        log.Printf("[Attacher] Failed to ensure clsact qdisc: %v", err)
        return nil, err
    }
    log.Printf("[Attacher] %s", msg)

    tcObjs, err := loadTCObjects()
    if err != nil {
        log.Printf("[Attacher] Failed to load TC objects: %v", err)
        return nil, err
    }

    tcingressfilter, err := AddBpfFilter(iface.Index, tcObjs.IngressProgFunc, PriorityTC, "tc_ingress_filter", "ingress")
    if err != nil {
        tcObjs.Close()
        log.Printf("[Attacher] Failed to add ingress filter: %v", err)
        return nil, err
    }
    log.Printf("[Attacher] Added ingress filter %q to interface %s (index %d)", tcingressfilter.Name, iface.Name, iface.Index)

    tcegressfilter, err := AddBpfFilter(iface.Index, tcObjs.EgressProgFunc, PriorityTC, "tc_egress_filter", "egress")
    if err != nil {
        DeleteFilter(tcingressfilter)
        tcObjs.Close()
        log.Printf("[Attacher] Failed to add egress filter: %v", err)
        return nil, err
    }
    log.Printf("[Attacher] Added egress filter %q to interface %s (index %d)", tcegressfilter.Name, iface.Name, iface.Index)

    return &BPFContext{
        NetnsName:       nsName,
        Iface:           iface,
        Name:            name,
        Qdisc:           qdisc,
        QdiscCreated:    created,
        TCbpfObjs:       tcObjs,
        TCIngressfilter: tcingressfilter,
        TCEgressfilter:  tcegressfilter,
    }, nil
}

// loadTCObjects loads the compiled eBPF TC programs and maps into a TCObjects struct.
func loadTCObjects() (*TCObjects, error) {
    objs := TCObjects{}
    if err := LoadTCObjects(&objs, nil); err != nil {
        return nil, fmt.Errorf("loading TC objects failed: %w", err)
    }
    return &objs, nil
}

// CleanupEBPF removes all eBPF filters, qdiscs, and objects for the given context.
func CleanupEBPF(ctx *BPFContext) {
    if ctx == nil {
        return
    }

    log.Printf("[Attacher] Cleaning up eBPF resources for interface %s", ctx.Iface.Name)

    var curNs netns.NsHandle
    var err error

    if ctx.NetnsName != "host" {
        curNs, err = cnflownetns.SwitchNetworkNamespace(ctx.NetnsName)
        if err != nil {
            log.Printf("[Attacher] Failed to switch to namespace %s for cleanup: %v", ctx.NetnsName, err)
            return
        }
        defer cnflownetns.RestoreNetNamespace(curNs)
    }

    if ctx.TCIngressfilter != nil {
        if err := DeleteFilter(ctx.TCIngressfilter); err != nil {
            log.Printf("[Attacher] Failed to delete ingress filter: %v", err)
        }
    }
    if ctx.TCEgressfilter != nil {
        if err := DeleteFilter(ctx.TCEgressfilter); err != nil {
            log.Printf("[Attacher] Failed to delete egress filter: %v", err)
        }
    }

    if ctx.QdiscCreated && ctx.Qdisc != nil {
        if err := DeleteQdisc(ctx.Qdisc); err != nil {
            log.Printf("[Attacher] Failed to delete qdisc: %v", err)
        }
    }

    if ctx.TCbpfObjs != nil {
        ctx.TCbpfObjs.Close()
    }

    log.Printf("[Attacher] Successfully cleaned up eBPF resources for interface %s", ctx.Iface.Name)
}

// StartEBPFMonitoring starts protocol monitoring on the given BPF context and blocks until stopChan is closed.
func StartEBPFMonitoring(stopChan <-chan struct{}, ctx *BPFContext) {
    log.Printf("[Attacher] Starting multi-protocol eBPF monitoring on interface %s", ctx.Iface.Name)

    startProtocolMonitoring(stopChan, ctx)

    <-stopChan
}
