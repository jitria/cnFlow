// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package k8s

import (
	"fmt"
	"log"
	"strings"
	"sync"

	"cnFlow/agent/config"
	"cnFlow/agent/resolver"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
)

type PodController struct {
	informerFactory informers.SharedInformerFactory
	podInformer     coreinformers.PodInformer
	mu              sync.RWMutex
	hostname        string
}

// NewPodController creates and returns a PodController with event handlers registered.
func NewPodController() (*PodController, error) {
	podInformer := K8sH.factory.Core().V1().Pods()

	c := &PodController{
		informerFactory: K8sH.factory,
		podInformer:     podInformer,
		mu:              sync.RWMutex{},
		hostname:        config.GlobalConfig.HostName,
	}

	podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*v1.Pod)
			if !ok || !strings.EqualFold(pod.Spec.NodeName, c.hostname) || pod.Namespace == "kube-system" {
				return
			}
			log.Printf("[PodController] Add Pod: %s/%s", pod.Namespace, pod.Name)

			resolver.ProcessPodEvent("ADD", pod)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			newPod, ok := newObj.(*v1.Pod)
			if !ok || !strings.EqualFold(newPod.Spec.NodeName, c.hostname) {
				return
			}
			log.Printf("[PodController] Update Pod: %s/%s", newPod.Namespace, newPod.Name)

			oldPod, ok := oldObj.(*v1.Pod)
			if !ok {
				return
			}
			resolver.ProcessPodUpdateEvent(oldPod, newPod)
		},
		DeleteFunc: func(obj interface{}) {
			pod, ok := obj.(*v1.Pod)
			if !ok || !strings.EqualFold(pod.Spec.NodeName, c.hostname) {
				return
			}
			log.Printf("[PodController] Delete Pod: %s/%s", pod.Namespace, pod.Name)

			resolver.ProcessPodEvent("DELETE", pod)
		},
	})

	return c, nil
}

// Run starts the informer factory and waits for the pod cache to sync.
func (c *PodController) Run(stopCh <-chan struct{}) error {
	c.informerFactory.Start(stopCh)
	if !cache.WaitForCacheSync(stopCh, c.podInformer.Informer().HasSynced) {
		return fmt.Errorf("failed to sync pod informer cache")
	}
	return nil
}
