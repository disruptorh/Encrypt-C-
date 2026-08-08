#ifndef ENCRYPT_SECURITY_SECCOMP_HPP_
#define ENCRYPT_SECURITY_SECCOMP_HPP_

namespace security {

// Install a seccomp-bpf filter that blocks the creation of network sockets
// (AF_INET / AF_INET6) at the syscall level.
//
// Rationale: the compile-time no_network_symbols test proves the shipped
// binary exposes no network entry points, but it cannot stop a runtime-loaded
// library (libGL, libX11) or a malicious LD_PRELOAD from calling socket().
// This filter closes that vector in the kernel itself.
//
// Unix-domain sockets are deliberately ALLOWED: both X11 and Wayland clients
// connect through AF_UNIX. Blocking only the AF_INET/AF_INET6 domains keeps
// the local display working while making TCP/UDP networking impossible.
//
// Returns true when the filter is installed (or the build architecture is not
// covered and the filter is intentionally a no-op). Returns false and emits a
// warning when the kernel refuses to install the filter (fail-open: the app
// still runs, minus this hardening).
bool install_seccomp_filter();

}  // namespace security

#endif  // ENCRYPT_SECURITY_SECCOMP_HPP_
