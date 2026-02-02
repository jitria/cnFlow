// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 BoanLab @ DKU

package k8s

import (
    "sync"
    "log"
    "os"
    "path/filepath"
    "time"

    "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type k8sHandler struct {
    waitGroup *sync.WaitGroup
    stopChan  chan struct{}

    config    *rest.Config
	clientSet *kubernetes.Clientset
	factory   informers.SharedInformerFactory

	nodeController *NodeController
	podController  *PodController
}

var (
    K8sH *k8sHandler
    kubeconfig = "/home/ubuntu/.kube/config"
)

// InitK8sHandler creates the K8s handler and initializes the client and controllers.
func InitK8sHandler(stopChan chan struct{}) error {
    var err error

    K8sH = &k8sHandler{
        stopChan:  stopChan,
        waitGroup: new(sync.WaitGroup),
    }

    if err = initK8sClient(); err != nil {
        return err
    }
    if err = initNodeController(); err != nil {
        return err
    }
    if err = initPodController(); err != nil {
        return err
    }

    return nil
}

// initK8sClient builds the Kubernetes client from the local kubeconfig file.
func initK8sClient() error {
	var err error

	if _, err := os.Stat(filepath.Clean(kubeconfig)); err != nil {
		log.Printf("[K8sHandler] Failed to find kubeconfig file: %v", err)
		return err
	}

	K8sH.config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		log.Printf("[K8sHandler] Failed to initialize Kubernetes client: %v", err)
		return err
	}

	K8sH.clientSet, err = kubernetes.NewForConfig(K8sH.config)
	if err != nil {
		log.Printf("[K8sHandler] Failed to initialize Kubernetes client: %v", err)
		return err
	}

	K8sH.factory = informers.NewSharedInformerFactory(K8sH.clientSet, time.Minute*10)

	return nil
}

// initNodeController creates and registers the node informer controller.
func initNodeController() error {
	var err error
	if K8sH.nodeController, err = NewNodeController(); err != nil {
		log.Printf("[K8sHandler] Error creating NodeController: %v", err)
		return err
	}

	return nil
}

// initPodController creates and registers the pod informer controller.
func initPodController() error {
	var err error
	if K8sH.podController, err = NewPodController(); err != nil {
		log.Printf("[K8sHandler] Error creating PodController: %v", err)
		return err
	}

	return nil
}

// StartK8sHandler launches the node and pod controllers in separate goroutines.
func StartK8sHandler() error {
    errCh := make(chan error, 2)

    K8sH.waitGroup.Add(1)
    go func() {
        defer K8sH.waitGroup.Done()
        if err := startNodeController(); err != nil {
            select {
            case errCh <- err:
            default:
            }
        }
    }()

    K8sH.waitGroup.Add(1)
    go func() {
        defer K8sH.waitGroup.Done()
        if err := startPodController(); err != nil {
            select {
            case errCh <- err:
            default:
            }
        }
    }()

    select {
    case err := <-errCh:
        return err
    case <-time.After(5 * time.Second):
        return nil
    }
}

// startNodeController runs the node controller and blocks until it finishes.
func startNodeController() error {
	err := K8sH.nodeController.Run(K8sH.stopChan)
	if err != nil {
		log.Printf("[K8sHandler] Error running NodeController: %v", err)
		return err
	}

	return nil
}

// startPodController runs the pod controller and blocks until it finishes.
func startPodController() error {
	err := K8sH.podController.Run(K8sH.stopChan)
	if err != nil {
		log.Printf("[K8sHandler] Error running PodController: %v", err)
		return err
	}

	return nil
}

// WaitShutdown blocks until all K8s goroutines have finished.
func WaitShutdown() {
    K8sH.waitGroup.Wait()
}
