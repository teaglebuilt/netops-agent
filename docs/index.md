

## Smoke Test

// Package main is the netops CI kernel-load smoke test. It exists to catch
// verifier rejections that compile-only CI cannot see: the BPF .o builds fine
// under clang but a real kernel rejects the program when the verifier walks
// it at load or attach time.
//
// Concretely, PRs #7-#9 each shipped a SRTT histogram that passed `make bpf`
// in CI and only blew up on the cluster:
//
//   - PR #7: "program of this type cannot use helper bpf_probe_read#4"
//     (fentry forbids probe_read helpers).
//   - PR #8: "permission denied: access beyond struct sock at off 1672 size
//     4" (the C-level cast to struct tcp_sock didn't satisfy the BPF type
//     system; bpf_skc_to_tcp_sock is the verifier-blessed narrowing).
//
// This binary is meant to be run inside a vmtest VM pinned to a kernel close
// to the production target (Talos ships 6.18.x). It:
//
//  1. Loads the embedded BPF object via ebpf.LoadCollectionSpecFromReader.
//  2. Calls ebpf.NewCollection — this is what walks the verifier and
//     surfaces the per-program rejection messages.
//  3. Attempts the same attach calls the production agent does (tcx ingress
//     on `lo`, fentry/fexit on the tracing programs). Some failures only
//     show up at attach time (e.g. missing kernel symbol), so loading alone
//     is not sufficient.
//  4. Reports SUCCESS / FAILURE per program with the underlying error text
//     and exits non-zero if any program failed.
//
// The smoke does NOT exercise the programs with traffic — that is explicitly
// out of scope (see issue #10). The goal is "verifier accepts and the kernel
// has the symbols we need", not "the agent produces correct metrics".