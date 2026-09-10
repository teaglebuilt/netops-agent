# Netops Agent

A per node daemonset watching network traffic and exposing as metrics for prometheus.

## Overview


```
┌────────────────────────────────────────────────┐
│ Node (×6: 3 CP + 3 worker)                     │
│                                                │
│  ┌───────────────┐    attach    ┌───────────┐  │
│  │ netscope-     │─────────────▶│ kernel    │  │
│  │ agent (pod)   │              │  tcx rx   │  │
│  │ hostNetwork   │              │  fentry×3 │  │
│  │ UID 0 / BPF + │              │  fexit×1  │  │
│  │ PERFMON +     │◀─────────────│           │  │
│  │ NET_ADMIN +   │  BPF maps    └───────────┘  │
│  │ SYS_ADMIN     │                             │
│  └───────┬───────┘                             │
│          │ :9101/metrics (hostPort)            │
└──────────┼─────────────────────────────────────┘
           │
           ▼
   ┌───────────────┐       ┌─────────────┐
   │ Prometheus    │──────▶│ Grafana     │
   │ (kps)         │       │ dashboard   │
   └───────────────┘       └─────────────┘
```

## Metrics

All series are per-node. Unless a label set is listed, the metric carries no
labels and therefore cannot be attributed to a peer, pod, connection, or slot.

### Host NIC (network path)

Anchored at tcx ingress **before** Cilium's `cil_from_netdev`, so these count
traffic Cilium may subsequently drop.

| Metric | Type | Labels | Source |
| --- | --- | --- | --- |
| `netops_rx_bytes_total` | counter | `iface` | `tcx/ingress` on the default-route interface |
| `netops_tcp_retransmits_total` | counter | — | `fentry/tcp_retransmit_skb` |
| `netops_tcp_srtt_microseconds` | histogram | — | `fentry/tcp_rcv_established` |
| `netops_dns_query_microseconds` | histogram | — | `fentry/udp_sendmsg` + `fexit/udp_recvmsg` |

Reading notes:

- `netops_tcp_retransmits_total` is node-global. It says retransmission is
  happening on the node, not which flow.
- `netops_tcp_srtt_microseconds` buckets are powers of two over the kernel's
  **scaled** `srtt_us` (actual µs × 8); the exported `le` labels are already
  converted to seconds. Only established connections receiving data contribute.
- `netops_dns_query_microseconds` covers **UDP DNS only** — TCP fallback, DoT and
  DoH are invisible. A query that never gets a response is never recorded, so
  timeouts appear as *missing* observations rather than slow ones.

### Host GPU / PCIe fabric

Scanned from the host `sysfs` mount (`NETOPS_SYSFS`, default `/host/sys`),
restricted to display (PCI class `0x03`) and processing-accelerator (class
`0x12`) functions. The NIC's own PCIe link is **not** covered.

| Metric | Type | Labels | Source |
| --- | --- | --- | --- |
| `netops_pci_device_present` | gauge | `slot`, `vendor`, `device`, `driver` | sysfs |
| `netops_pci_link_speed_gtps` | gauge | `slot`, `vendor`, `device`, `driver` | sysfs `current_link_speed` |
| `netops_pci_link_width` | gauge | `slot`, `vendor`, `device`, `driver` | sysfs `current_link_width` |
| `netops_pci_link_speed_max_gtps` | gauge | `slot`, `vendor`, `device`, `driver` | sysfs `max_link_speed` |
| `netops_pci_link_width_max` | gauge | `slot`, `vendor`, `device`, `driver` | sysfs `max_link_width` |
| `netops_pci_aer_errors` | gauge | `slot`, `vendor`, `device`, `driver`, `severity` | sysfs `aer_dev_{correctable,nonfatal,fatal}` |
| `netops_pci_probe_total` | counter | — | `fentry/pci_bus_add_device` |
| `netops_pci_remove_total` | counter | — | `fentry/pci_stop_and_remove_bus_device` |
| `netops_thunderbolt_authorized` | gauge | `id`, `name` | sysfs |

Reading notes:

- `netops_pci_device_present` and `netops_thunderbolt_authorized` are **sticky**:
  once a device has been observed it keeps reporting, flipping to `0` if it later
  disappears. A `1 → 0` transition is a real drop; a device never observed is
  absent from the series entirely, which is not the same as `0`.
- Link health is the **comparison** `current` vs `max`, not the absolute value.
  Many GPUs deliberately downtrain at idle under ASPM and retrain under load, so
  a low current speed on an idle device is not by itself a fault. When
  `netops_pci_device_present` is `0` the link gauges are omitted entirely, not
  zeroed — `device_present` already carries the fact, and a zeroed gauge would
  be indistinguishable from a link that trained down to nothing.
- The four link gauges are only emitted when the kernel actually reported a
  link: a Thunderbolt-tunnelled eGPU has no native PCIe link to train, so
  `current_link_*`/`max_link_*` read back as the unknown sentinel (`EINVAL`,
  `"Unknown"`, `255` lanes) rather than a real value, and a passed-through
  function in a guest VM reports its own sentinel (`63` lanes). The collector
  suppresses the series in both cases instead of publishing a fake `0 GT/s` /
  `255`-lane reading that would look like catastrophic degradation on healthy
  hardware. See `NETOPS_ROLE` below and `docs/index.md` for the full host/guest
  vantage-point story.
- `netops_pci_aer_errors` is a **snapshot** of the kernel's counters exposed as a
  gauge, not a scrape counter. Compare values across timestamps for a delta; it
  resets to `0` on reboot or driver rebind. The series exists only where the
  kernel has AER enabled and the function exposes the files — absence means "not
  reported", never "zero errors".
- `netops_pci_probe_total` / `netops_pci_remove_total` are unlabelled and
  GPU-class filtered. Identify *which* device by pairing a rise in
  `remove_total` with the slot whose `netops_pci_device_present` went `1 → 0`.
  Both programs are **optional**: where the kernel lacks the symbols the agent
  logs a warning and serves sysfs metrics only, so these series can be missing on
  a node whose sysfs gauges are healthy.

## Configuration

| Env var | Chart value | Default | Purpose |
| --- | --- | --- | --- |
| `NETOPS_DEVICE` | `iface` | *(auto)* | Interface for the tcx ingress program. Empty discovers the default-route NIC from `/proc/net/route`. |
| `NETOPS_SYSFS` | `pcie.sysfsRoot` | `/host/sys` | Host sysfs mount used by the PCIe/Thunderbolt scan. |
| `NETOPS_ROLE` | `pcie.role` | `host` | `host` or `guest`. Gates link, AER and Thunderbolt series — a VFIO passthrough boundary splits what's observable in two, and a guest VM only ever exports `netops_pci_device_present`. Defaults to `host` (full fidelity) so a deployment that forgets to set it loses no data; the Helm chart sets `guest` since the DaemonSet runs on Talos VMs. See `docs/index.md`. |
