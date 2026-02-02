// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package attacher

import (
    "sync"
    "log"

    "cnFlow/types"

    "github.com/cilium/ebpf/rlimit"
    "github.com/vishvananda/netlink"
)

type attacherHandler struct {
    waitGroup *sync.WaitGroup
    stopChan  chan struct{}
}

type BPFContext struct {
    Iface            types.NetworkInterfaceInfo
    NetnsName        string
    Name             string
    Qdisc            netlink.Qdisc
    QdiscCreated     bool

    TCbpfObjs        *TCObjects
    TCIngressfilter  *netlink.BpfFilter
    TCEgressfilter   *netlink.BpfFilter
}

const (
    PriorityTC = 1
)

var AttacherH *attacherHandler

// InitAttacherHandler creates the attacher handler and removes the memlock rlimit for eBPF.
func InitAttacherHandler(stopChan chan struct{}) error {
    AttacherH = &attacherHandler{
        stopChan:  stopChan,
        waitGroup: new(sync.WaitGroup),
    }

    if err := rlimit.RemoveMemlock(); err != nil {
        log.Printf("[Attacher] Warning: failed to remove memlock limit: %v", err)
    }

    log.Printf("[Attacher] Attacher handler initialized")
    return nil
}

// StartAttacherHandler is a placeholder for future start-up logic.
func StartAttacherHandler() error {
    log.Printf("[Attacher] Attacher handler started")
    return nil
}

// WaitShutdown blocks until all attacher goroutines have finished.
func WaitShutdown() {
    AttacherH.waitGroup.Wait()
    log.Printf("[Attacher] All attacher goroutines stopped")
}
