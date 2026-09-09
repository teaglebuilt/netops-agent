## HOST NIC Observability

```mermaid
flowchart TB
    subgraph kernel["KERNEL SPACE (BPF programs + maps)"]
        direction TB
        nic["Host NIC (default-route iface)"]
        rxprog["count_rx<br/>SEC tcx/ingress<br/>reads skb->len, returns TC_ACT_UNSPEC"]
        retxprog["count_tcp_retransmit<br/>SEC fentry/tcp_retransmit_skb"]
        srttprog["record_tcp_srtt<br/>SEC fentry/tcp_rcv_established<br/>bpf_skc_to_tcp_sock -> srtt_us -> log2 bucket"]
        dnsqprog["record_dns_query<br/>SEC fentry/udp_sendmsg<br/>dport==53: stash start ts by 4-tuple"]
        dnsrprog["record_dns_response<br/>SEC fexit/udp_recvmsg<br/>ret>0 & dport==53: delta -> log2 bucket"]

        rxmap[("netscope_rx_bytes<br/>PERCPU_ARRAY[1]")]
        retxmap[("netscope_tcp_retransmits<br/>PERCPU_ARRAY[1]")]
        srttmap[("netscope_tcp_srtt_buckets<br/>PERCPU_ARRAY[24]")]
        dnsstarts[("netscope_dns_query_starts<br/>HASH[8192] 4-tuple -> ns")]
        dnsmap[("netscope_dns_latency_buckets<br/>PERCPU_ARRAY[24]")]

        nic --> rxprog --> rxmap
        retxprog --> retxmap
        srttprog --> srttmap
        dnsqprog -->|write start ts| dnsstarts
        dnsstarts -->|lookup + delete| dnsrprog
        dnsrprog --> dnsmap
    end

    subgraph user["USERSPACE (cmd/agent — Go)"]
        direction TB
        loader["loader: rlimit.RemoveMemlock<br/>LoadCollectionSpecFromReader(embedded .o)<br/>NewCollection -> AttachTCX / AttachTracing"]
        collectors["Prometheus collectors<br/>CounterFunc x2 + custom Histogram collectors x2<br/>read maps at scrape, sum per-CPU, build le buckets"]
        http["net/http mux<br/>/metrics (promhttp) + /healthz"]
    end

    scraper["Prometheus / ServiceMonitor<br/>scrape http://:9101/metrics"]

    loader -. "attach (BPF syscall)" .-> rxprog
    loader -. attach .-> retxprog
    loader -. attach .-> srttprog
    loader -. attach .-> dnsqprog
    loader -. attach .-> dnsrprog

    rxmap -.->|"map lookup (scrape)"| collectors
    retxmap -.->|map lookup| collectors
    srttmap -.->|map lookup| collectors
    dnsmap -.->|map lookup| collectors

    collectors --> http
    scraper -->|GET /metrics| http

    linkStyle default stroke-width:1px
```

## Host PCI Observability

The agent monitors the **host** path an eGPU takes onto the bus. It does not
report GPU PCIe byte counters: after VFIO passthrough, that DMA never hits
the host kernel. Run DCGM or `nvidia-smi` **inside the GPU VM** for
throughput, util, and VRAM.

```mermaid
flowchart LR
  subgraph host["Host (netops-agent DaemonSet)"]
    TP["fentry pci_bus_add_device / pci_stop_and_remove_bus_device"]
    SYS["sysfs on scrape\nPCI link + AER + Thunderbolt"]
    MAPS["PERCPU GPU-class add/remove counters"]
    PROM["/metrics :9101"]
    TP --> MAPS
    SYS --> PROM
    MAPS --> PROM
  end

  subgraph guest["GPU VM"]
    DCGM["DCGM or nvidia-smi exporter"]
    NVML["NVML PCIe TX/RX"]
    NVML --> DCGM
  end

  GPU["eGPU over Thunderbolt"] --> SYS
  GPU --> NVML
  PROM --> Grafana
  DCGM --> Grafana
```

## What is collected

| Metric | Source | Notes |
|---|---|---|
| `netops_pci_device_present` | sysfs | GPU-class functions only (`0x03xxxx` display, `0x12xxxx` accelerator). Stays `0` after unplug. |
| `netops_pci_link_speed_gtps` / `netops_pci_link_width` | sysfs | Negotiated link. Alert if below expected (e.g. not 8 GT/s × 4). |
| `netops_pci_link_speed_max_gtps` / `netops_pci_link_width_max` | sysfs | Advertised cap; compare to negotiated for retrains. |
| `netops_pci_aer_errors` | sysfs `aer_dev_*` | Omitted when AER files are absent. Snapshot of the status registers. |
| `netops_pci_probe_total` / `netops_pci_remove_total` | eBPF fentry | Optional. Agent still runs if attach fails. |
| `netops_thunderbolt_authorized` | sysfs | Enclosure authorization. |

Labels: `slot`, `vendor`, `device`, `driver` (PCI); `id`, `name` (Thunderbolt).

## Runtime

- `NETOPS_SYSFS` — sysfs root. Default `/sys`. The DaemonSet mounts host `/sys` at `/host/sys` and sets this to `/host/sys`.
- PCI BPF attach is best-effort. Sysfs gauges always register.

Guest bandwidth (out of scope here): `DCGM_FI_PROF_PCIE_TX_BYTES` / `DCGM_FI_PROF_PCIE_RX_BYTES` or NVML `nvmlDeviceGetPcieThroughput`.


## Host Nic Observability

```mermaid
flowchart TB
    subgraph kernel["KERNEL SPACE (BPF programs + maps)"]
        direction TB
        nic["Host NIC (default-route iface)"]
        rxprog["count_rx<br/>SEC tcx/ingress<br/>reads skb->len, returns TC_ACT_UNSPEC"]
        retxprog["count_tcp_retransmit<br/>SEC fentry/tcp_retransmit_skb"]
        srttprog["record_tcp_srtt<br/>SEC fentry/tcp_rcv_established<br/>bpf_skc_to_tcp_sock -> srtt_us -> log2 bucket"]
        dnsqprog["record_dns_query<br/>SEC fentry/udp_sendmsg<br/>dport==53: stash start ts by 4-tuple"]
        dnsrprog["record_dns_response<br/>SEC fexit/udp_recvmsg<br/>ret>0 & dport==53: delta -> log2 bucket"]

        rxmap[("netscope_rx_bytes<br/>PERCPU_ARRAY[1]")]
        retxmap[("netscope_tcp_retransmits<br/>PERCPU_ARRAY[1]")]
        srttmap[("netscope_tcp_srtt_buckets<br/>PERCPU_ARRAY[24]")]
        dnsstarts[("netscope_dns_query_starts<br/>HASH[8192] 4-tuple -> ns")]
        dnsmap[("netscope_dns_latency_buckets<br/>PERCPU_ARRAY[24]")]

        nic --> rxprog --> rxmap
        retxprog --> retxmap
        srttprog --> srttmap
        dnsqprog -->|write start ts| dnsstarts
        dnsstarts -->|lookup + delete| dnsrprog
        dnsrprog --> dnsmap
    end

    subgraph user["USERSPACE (cmd/agent — Go)"]
        direction TB
        loader["loader: rlimit.RemoveMemlock<br/>LoadCollectionSpecFromReader(embedded .o)<br/>NewCollection -> AttachTCX / AttachTracing"]
        collectors["Prometheus collectors<br/>CounterFunc x2 + custom Histogram collectors x2<br/>read maps at scrape, sum per-CPU, build le buckets"]
        http["net/http mux<br/>/metrics (promhttp) + /healthz"]
    end

    scraper["Prometheus / ServiceMonitor<br/>scrape http://:9101/metrics"]

    loader -. "attach (BPF syscall)" .-> rxprog
    loader -. attach .-> retxprog
    loader -. attach .-> srttprog
    loader -. attach .-> dnsqprog
    loader -. attach .-> dnsrprog

    rxmap -.->|"map lookup (scrape)"| collectors
    retxmap -.->|map lookup| collectors
    srttmap -.->|map lookup| collectors
    dnsmap -.->|map lookup| collectors

    collectors --> http
    scraper -->|GET /metrics| http

    linkStyle default stroke-width:1px
```
