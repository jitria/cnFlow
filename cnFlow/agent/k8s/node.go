// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package k8s

import (
	"fmt"
	"log"
	"sync"
	"strings"

	"cnFlow/agent/resolver"
	"cnFlow/agent/config"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
)

type NodeController struct {
	informerFactory informers.SharedInformerFactory
	nodeInformer    coreinformers.NodeInformer

	mu 			sync.RWMutex
	hostname    string
}

// NewNodeController creates and returns a NodeController with event handlers registered.
func NewNodeController() (*NodeController, error) {
	nodeInformer := K8sH.factory.Core().V1().Nodes()

	c := &NodeController{
		informerFactory: K8sH.factory,
		nodeInformer:    nodeInformer,

		mu: sync.RWMutex{},
		hostname:  config.GlobalConfig.HostName,
	}

	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
    AddFunc: func(obj interface{}) {
        node, ok := obj.(*v1.Node)
        if !ok {
            return
        }

        if !strings.EqualFold(node.Name, c.hostname) {
            return
        }

        log.Printf("[NodeController] Add Node: %s", node.Name)
        resolver.ProcessNodeEvent("ADD", node)
    },
    UpdateFunc: func(oldObj, newObj interface{}) {
        newNode, ok := newObj.(*v1.Node)
        if !ok {
            return
        }

        if !strings.EqualFold(newNode.Name, c.hostname) {
            return
        }

        log.Printf("[NodeController] Update Node: %s", newNode.Name)
        oldNode, ok := oldObj.(*v1.Node)
        if !ok {
            return
        }
        resolver.ProcessNodeUpdateEvent(oldNode, newNode)
    },
    DeleteFunc: func(obj interface{}) {
        node, ok := obj.(*v1.Node)
        if !ok {
            return
        }

        if !strings.EqualFold(node.Name, c.hostname) {
            return
        }

        log.Printf("[NodeController] Delete Node: %s", node.Name)
        resolver.ProcessNodeEvent("DELETE", node)
    },
})


	return c, nil
}

// Run starts the informer factory and waits for the node cache to sync.
func (c *NodeController) Run(stopCh <-chan struct{}) error {
	c.informerFactory.Start(stopCh)

	if !cache.WaitForCacheSync(stopCh, c.nodeInformer.Informer().HasSynced) {
		return fmt.Errorf("failed to sync")
	}

	return nil
}
