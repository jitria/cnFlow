# cnFlow

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/Go-1.24-blue.svg)](https://golang.org/)
[![BPF](https://img.shields.io/badge/BPF-eBPF-green.svg)](https://ebpf.io/)

cnFlow is a cloud-native network observability system that leverages eBPF/TC to capture, enrich, and analyze application-layer protocol traffic across Kubernetes pods and nodes in real time with minimal overhead.

## Supported Protocols

| Protocol | Description |
|----------|-------------|
| HTTP     | HTTP/1.x request and response capture |
| HTTP/2   | HTTP/2 frame capture with HPACK header decoding |
| DNS      | DNS query and response analysis |
| Redis    | Redis command and response capture |
| Kafka    | Kafka API request and response capture |
| ICMP     | ICMP echo and error message capture |

## Deployment

### Prerequisites

- Kubernetes cluster (v1.28+)
- Linux kernel 5.15+ with eBPF support
- Nodes with `NET_ADMIN`, `SYS_ADMIN` capabilities

### Kubernetes Deployment

```bash
kubectl apply -f deployments/ns.yaml       # 1. Namespace, ServiceAccount, RBAC
kubectl apply -f deployments/manager.yaml   # 2. Manager Pod
kubectl apply -f deployments/agent.yaml     # 3. Agent DaemonSet
```

### Build from Source

```bash
cd cnFlow

# Build binaries
go build -o agent ./agent/main.go
go build -o manager ./manager/main.go
```

### Docker Build

```bash
# Build agent image
docker build --target agent -t cnflow-agent:latest -f deployments/Dockerfile .

# Build manager image
docker build --target manager -t cnflow-manager:latest -f deployments/Dockerfile .
```

## Development

### Prerequisites

- Go 1.24+
- Clang 14+ / LLVM 14+
- Linux headers (`linux-headers-$(uname -r)`)
- `bpftool`, `iproute2`

### Project Structure

```
cnFlow/
├── go.mod
├── types/          # Shared type definitions
├── protobuf/       # gRPC proto and generated code
├── agent/
│   ├── main.go
│   ├── config/     # Agent configuration
│   ├── core/       # Agent lifecycle
│   ├── attacher/   # eBPF program loading and TC setup
│   ├── k8s/        # Kubernetes pod/node informers
│   ├── netns/      # Network namespace operations
│   ├── resolver/   # Pod/node event resolution and eBPF orchestration
│   └── uploader/   # gRPC streaming to manager
└── manager/
    ├── main.go
    ├── config/     # Manager configuration
    ├── core/       # Manager lifecycle
    ├── collector/  # gRPC server receiving agent streams
    ├── parser/     # Protocol-specific log parsing and formatting
    └── mixer/      # Flow enrichment (K8s metadata, GeoIP, metrics)
```

### Configuration

**Agent** (`--hostname`, `--managerAddr`, `--managerPort`):

```bash
./agent --hostname=worker1 --managerAddr=10.0.0.1 --managerPort=5317
```

**Manager** (`--hostname`, `--managerAddr`, `--managerPort`):

```bash
./manager --managerAddr=0.0.0.0 --managerPort=5317
```

## gRPC Streaming API

cnFlow uses unidirectional gRPC streaming from agents to the manager:

```protobuf
service cnFlow {
  rpc SyncPods (stream PodInfo) returns (Ack);
  rpc SyncNodes (stream NodeInfo) returns (Ack);
  rpc HTTPEvents (stream HTTPEvent) returns (Ack);
  rpc HTTP2Events (stream HTTP2Event) returns (Ack);
  rpc DNSEvents (stream DNSEvent) returns (Ack);
  rpc RedisEvents (stream RedisEvent) returns (Ack);
  rpc ICMPEvents (stream ICMPEvent) returns (Ack);
  rpc KafkaEvents (stream KafkaEvent) returns (Ack);
}
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

---

**Copyright 2025 [BoanLab](https://boanlab.com) @ DKU**
