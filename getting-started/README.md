# Getting Started with cnFlow

This guide will help you quickly get started with cnFlow and experience its core features in just a few minutes.

## What is cnFlow?

cnFlow is a cloud-native network observability system that captures and analyzes application-layer protocol traffic at the kernel level using eBPF/TC technology. It provides:

- **Real-time packet capture** of HTTP, HTTP/2, DNS, Redis, Kafka, and ICMP traffic across Kubernetes pods and nodes
- **Protocol-aware parsing** with detailed field extraction (headers, queries, commands, API keys)
- **gRPC streaming** from per-node agents to a centralized manager for aggregation and export

## Quick Start

### Step 1: Deploy cnFlow

Deploy cnFlow to your Kubernetes cluster:

```bash
# Clone the repository
git clone https://github.com/BoanLab/cnFlow.git
cd cnFlow

# Create namespace, ServiceAccount, and RBAC
kubectl apply -f deployments/ns.yaml

# Deploy Manager
kubectl apply -f deployments/manager.yaml

# Deploy Agent DaemonSet
kubectl apply -f deployments/agent.yaml

# Wait for pods to be ready
kubectl wait --for=condition=ready pod -l app=cnflow-agent -n cnflow --timeout=60s
kubectl wait --for=condition=ready pod -l app=cnflow-manager -n cnflow --timeout=60s
```

### Step 2: Verify Agent-Manager Connection

Check that agents are streaming data to the manager:

```bash
# Check manager logs for incoming streams
kubectl logs -n cnflow cnflow-manager

# Check agent logs on a specific node
kubectl logs -n cnflow -l app=cnflow-agent --tail=20
```

### Step 3: Generate Test Traffic

Send HTTP requests to verify the capture pipeline:

```bash
# From any pod in the cluster, send an HTTP request
kubectl run curl-test --image=curlimages/curl --rm -it --restart=Never -- \
  curl -s http://<target-service>
```

### Step 4: Observe Parsed Output

Check the manager logs for parsed protocol data:

```bash
kubectl logs -n cnflow cnflow-manager --tail=50
```

## Example: Monitoring Application Traffic

### HTTP

cnFlow automatically captures HTTP/1.x request and response traffic:

```
HTTP | Method=GET | URL=/api/v1/users | Status=200 | Src=frontend-pod(10.244.1.5:43210) | Dst=backend-pod(10.244.2.3:8080)
```

### HTTP/2

HTTP/2 frames are decoded with HPACK header decompression:

```
HTTP2 | FrameType=HEADERS | StreamID=1 | Headers=[:method: POST, :path: /api/v1/data]
```

### DNS

DNS queries and responses are captured and analyzed:

```
DNS | Type=A | Query=example.com | Response=93.184.216.34
```

### Redis

Redis commands and responses are captured:

```
Redis | Command=GET | Key=session:abc123
```

### Kafka

Kafka API requests and responses are captured:

```
Kafka | APIKey=Produce | Topic=events | Partition=0
```

### ICMP

ICMP echo and error messages are captured:

```
ICMP | Type=Echo Request | Code=0 | Src=10.244.1.5 | Dst=10.244.2.3
```

## Build from Source

```bash
cd cnFlow

# Build binaries
go build -o agent ./agent/main.go
go build -o manager ./manager/main.go

# Run locally (requires root for eBPF)
sudo ./agent --hostname=$(hostname) --managerAddr=<manager-ip> --managerPort=5317
./manager --managerAddr=0.0.0.0 --managerPort=5317
```

## Cleanup

Remove cnFlow from the cluster:

```bash
kubectl delete -f deployments/agent.yaml
kubectl delete -f deployments/manager.yaml
kubectl delete -f deployments/ns.yaml
```

---

Need help? [Open an issue on GitHub](https://github.com/BoanLab/cnFlow/issues).
