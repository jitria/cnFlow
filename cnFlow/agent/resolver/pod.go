// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package resolver

import (
    "fmt"
    "log"
    "strings"

    v1 "k8s.io/api/core/v1"
    "cnFlow/types"
    "cnFlow/agent/attacher"
    "cnFlow/agent/uploader"
)

// ProcessPodEvent dispatches pod add/delete events to the appropriate handler.
func ProcessPodEvent(eventType string, pod *v1.Pod) {
    switch eventType {
    case "ADD":
        handlePodAdd(pod)
    case "DELETE":
        handlePodDelete(pod)
    default:
        log.Printf("[Resolver] Unknown pod event type: %s", eventType)
    }
}

// ProcessPodUpdateEvent handles pod update events.
func ProcessPodUpdateEvent(oldPod, newPod *v1.Pod) {
    handlePodUpdate(oldPod, newPod)
}

// handlePodAdd registers the pod IPs and sets up eBPF monitoring for it.
func handlePodAdd(pod *v1.Pod) {
    log.Printf("[Resolver] Processing pod add: %s/%s", pod.Namespace, pod.Name)

    podInfo := convertPodToPodInfo(pod)

    registerPodIPs(podInfo)

    setupEBPFForPod(podInfo)
}

// handlePodUpdate re-registers the pod IPs and updates eBPF if needed.
func handlePodUpdate(oldPod, newPod *v1.Pod) {
    log.Printf("[Resolver] Processing pod update: %s/%s", newPod.Namespace, newPod.Name)

    oldPodInfo := convertPodToPodInfo(oldPod)
    unregisterPodIPs(oldPodInfo)

    newPodInfo := convertPodToPodInfo(newPod)
    registerPodIPs(newPodInfo)

    if shouldUpdatePodEBPF(oldPodInfo, newPodInfo) {
        cleanupEBPFForPod(oldPodInfo)
        setupEBPFForPod(newPodInfo)
    }
}

// handlePodDelete unregisters the pod IPs and cleans up eBPF resources.
func handlePodDelete(pod *v1.Pod) {
    log.Printf("[Resolver] Processing pod delete: %s/%s", pod.Namespace, pod.Name)

    podInfo := convertPodToPodInfo(pod)

    unregisterPodIPs(podInfo)

    cleanupEBPFForPod(podInfo)
}

// convertPodToPodInfo converts a Kubernetes Pod object to the internal PodInfo type.
func convertPodToPodInfo(pod *v1.Pod) types.PodInfo {
    var podNs *types.NetworkNamespaceInfo

    if pod.Spec.HostNetwork {
        podNs = collectHostNamespaceInfo()
    } else {
        podNs = findPodNetworkNamespace(pod)
    }

    netNsInfo := types.NetworkNamespaceInfo{}
    if podNs != nil {
        netNsInfo = *podNs
    }

    return types.PodInfo{
        Name:        pod.Name,
        Namespace:   pod.Namespace,
        Phase:       string(pod.Status.Phase),
        PodIP:       pod.Status.PodIP,
        PodUID:      string(pod.UID),
        Node:        pod.Spec.NodeName,
        HostIP:      pod.Status.HostIP,
        HostNetwork: pod.Spec.HostNetwork,
        NetNsInfo:   netNsInfo,

        ServiceAccount: extractServiceAccountInfo(pod),
        SecurityContext: extractSecurityContextInfo(pod),
    }
}

// registerPodIPs adds all pod IP addresses to the uploader pod map.
func registerPodIPs(podInfo types.PodInfo) {
    uploader.RegisterPodToMap(podInfo.PodIP, podInfo)

    for _, iface := range podInfo.NetNsInfo.Interfaces {
        for _, ip := range iface.IPv4Addrs {
            uploader.RegisterPodToMap(ip, podInfo)
            log.Printf("[Resolver] Registered Pod IP: %s for pod %s/%s", ip, podInfo.Namespace, podInfo.Name)
        }
    }
}

// unregisterPodIPs removes all pod IP addresses from the uploader pod map.
func unregisterPodIPs(podInfo types.PodInfo) {
    uploader.UnregisterPodFromMap(podInfo.PodIP)

    for _, iface := range podInfo.NetNsInfo.Interfaces {
        for _, ip := range iface.IPv4Addrs {
            uploader.UnregisterPodFromMap(ip)
            log.Printf("[Resolver] Unregistered Pod IP: %s for pod %s/%s", ip, podInfo.Namespace, podInfo.Name)
        }
    }
}

// findPodNetworkNamespace finds the network namespace matching the pod's IP address.
func findPodNetworkNamespace(pod *v1.Pod) *types.NetworkNamespaceInfo {
    userNsList := collectUserNamespaceInfo()

    for _, nsInfo := range userNsList {
        for _, iface := range nsInfo.Interfaces {
            for _, ip := range iface.IPv4Addrs {
                if pod.Status.PodIP == ip {
                    return &nsInfo
                }
            }
        }
    }

    return nil
}

// extractServiceAccountInfo extracts the service account details from a pod spec.
func extractServiceAccountInfo(pod *v1.Pod) types.ServiceAccountInfo {
    serviceAccountName := pod.Spec.ServiceAccountName
    if serviceAccountName == "" {
        serviceAccountName = "default"
    }

    var secrets []string
    var imagePullSecrets []string

    for _, secret := range pod.Spec.ImagePullSecrets {
        imagePullSecrets = append(imagePullSecrets, secret.Name)
    }

    automount := true
    if pod.Spec.AutomountServiceAccountToken != nil {
        automount = *pod.Spec.AutomountServiceAccountToken
    }

    return types.ServiceAccountInfo{
        Name:                         serviceAccountName,
        Namespace:                    pod.Namespace,
        AutomountServiceAccountToken: automount,
        Secrets:                      secrets,
        ImagePullSecrets:             imagePullSecrets,
    }
}

// extractSecurityContextInfo extracts the security context from the pod and its first container.
func extractSecurityContextInfo(pod *v1.Pod) types.SecurityContextInfo {
    securityContext := types.SecurityContextInfo{}

    if pod.Spec.SecurityContext != nil {
        podSC := pod.Spec.SecurityContext

        if podSC.RunAsNonRoot != nil {
            securityContext.RunAsNonRoot = *podSC.RunAsNonRoot
        }
        if podSC.RunAsUser != nil {
            securityContext.RunAsUser = podSC.RunAsUser
        }
        if podSC.RunAsGroup != nil {
            securityContext.RunAsGroup = podSC.RunAsGroup
        }
        if podSC.FSGroup != nil {
            securityContext.FSGroup = podSC.FSGroup
        }
        if podSC.SELinuxOptions != nil {
            securityContext.SELinuxOptions = podSC.SELinuxOptions.Type
        }
    }

    // Use the first container's security context as representative
    if len(pod.Spec.Containers) > 0 && pod.Spec.Containers[0].SecurityContext != nil {
        containerSC := pod.Spec.Containers[0].SecurityContext

        if containerSC.Privileged != nil {
            securityContext.Privileged = *containerSC.Privileged
        }
        if containerSC.AllowPrivilegeEscalation != nil {
            securityContext.AllowPrivilegeEscalation = *containerSC.AllowPrivilegeEscalation
        }

        if containerSC.Capabilities != nil {
            for _, cap := range containerSC.Capabilities.Add {
                securityContext.CapabilitiesAdd = append(securityContext.CapabilitiesAdd, string(cap))
            }
            for _, cap := range containerSC.Capabilities.Drop {
                securityContext.CapabilitiesDrop = append(securityContext.CapabilitiesDrop, string(cap))
            }
        }
    }

    return securityContext
}

// setupEBPFForPod attaches TC eBPF programs to all interfaces of the pod.
func setupEBPFForPod(podInfo types.PodInfo) {
    log.Printf("[Resolver] Setting up eBPF for pod: %s/%s", podInfo.Namespace, podInfo.Name)

    for _, iface := range podInfo.NetNsInfo.Interfaces {
        ctx, err := attacher.SetupTC(podInfo.NetNsInfo.Name, iface, podInfo.Name)
        if err != nil {
            log.Printf("[Resolver] Failed to setup eBPF for pod %s interface %s: %v",
                podInfo.Name, iface.Name, err)
            continue
        }

        startPodEBPFMonitoring(podInfo, iface, ctx)
    }
}

// startPodEBPFMonitoring launches a goroutine to monitor eBPF events for a pod interface.
func startPodEBPFMonitoring(podInfo types.PodInfo, iface types.NetworkInterfaceInfo, ctx *attacher.BPFContext) {
    stopChan := make(chan struct{})
    key := fmt.Sprintf("%s|%s", podInfo.Name, iface.Name)
    addPodStopChan(key, stopChan)

    ResolverH.waitGroup.Add(1)
    go func() {
        defer ResolverH.waitGroup.Done()
        defer func() {
            attacher.CleanupEBPF(ctx)
            removePodStopChan(key)
        }()

        attacher.StartEBPFMonitoring(stopChan, ctx)

        <-stopChan
        log.Printf("[Resolver] Stopped eBPF monitoring for pod %s interface %s", podInfo.Name, iface.Name)
    }()
}

// cleanupEBPFForPod closes all eBPF stop channels associated with the pod.
func cleanupEBPFForPod(podInfo types.PodInfo) {
    log.Printf("[Resolver] Cleaning up eBPF for pod: %s/%s", podInfo.Namespace, podInfo.Name)

    prefix := podInfo.Name + "|"
    ResolverH.mu.Lock()
    var keysToDelete []string
    for key := range ResolverH.podStopChans {
        if strings.HasPrefix(key, prefix) {
            keysToDelete = append(keysToDelete, key)
        }
    }
    ResolverH.mu.Unlock()

    for _, key := range keysToDelete {
        removePodStopChan(key)
    }
}

// shouldUpdatePodEBPF returns true if the pod change requires eBPF reattachment.
func shouldUpdatePodEBPF(oldPodInfo, newPodInfo types.PodInfo) bool {
    return oldPodInfo.PodIP != newPodInfo.PodIP ||
           oldPodInfo.Phase != newPodInfo.Phase ||
           oldPodInfo.HostNetwork != newPodInfo.HostNetwork
}

// addPodStopChan registers a stop channel for a pod interface monitoring goroutine.
func addPodStopChan(key string, stopChan chan struct{}) {
    ResolverH.mu.Lock()
    defer ResolverH.mu.Unlock()
    ResolverH.podStopChans[key] = stopChan
}

// removePodStopChan closes and removes the stop channel for a pod interface.
func removePodStopChan(key string) {
    ResolverH.mu.Lock()
    defer ResolverH.mu.Unlock()
    if stopChan, exists := ResolverH.podStopChans[key]; exists {
        close(stopChan)
        delete(ResolverH.podStopChans, key)
    }
}
