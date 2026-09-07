#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/* CO-RE subset of struct pci_dev. Field names must match the kernel. */
struct pci_dev {
	unsigned short vendor;
	unsigned short device;
	unsigned int class;
} __attribute__((preserve_access_index));

#define PCI_BASE_CLASS_DISPLAY 0x03
#define PCI_BASE_CLASS_PROCESSING_ACCEL 0x12

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} netops_pci_probe_total SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} netops_pci_remove_total SEC(".maps");

static __always_inline int is_gpu_class(__u32 class)
{
	__u32 base = (class >> 16) & 0xff;
	return base == PCI_BASE_CLASS_DISPLAY ||
	       base == PCI_BASE_CLASS_PROCESSING_ACCEL;
}

SEC("fentry/pci_bus_add_device")
int BPF_PROG(count_pci_add, struct pci_dev *dev)
{
	__u32 key = 0;
	__u64 *val;

	if (!dev) {
		return 0;
	}
	if (!is_gpu_class(dev->class)) {
		return 0;
	}
	val = bpf_map_lookup_elem(&netops_pci_probe_total, &key);
	if (val) {
		__sync_fetch_and_add(val, 1);
	}
	return 0;
}

SEC("fentry/pci_stop_and_remove_bus_device")
int BPF_PROG(count_pci_remove, struct pci_dev *dev)
{
	__u32 key = 0;
	__u64 *val;

	if (!dev) {
		return 0;
	}
	if (!is_gpu_class(dev->class)) {
		return 0;
	}
	val = bpf_map_lookup_elem(&netops_pci_remove_total, &key);
	if (val) {
		__sync_fetch_and_add(val, 1);
	}
	return 0;
}
