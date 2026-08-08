#include "security/seccomp.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>

#include <sys/prctl.h>
#include <sys/syscall.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

namespace security {
namespace {

constexpr std::size_t kArg0Offset = 16;  // offsetof(seccomp_data, args[0])

// A socket() call is only a network risk when the requested domain is AF_INET
// or AF_INET6. AF_UNIX (X11/Wayland) and AF_NETLINK etc. are allowed.
constexpr std::uint32_t kAfInet = 2;
constexpr std::uint32_t kAfInet6 = 10;

}  // namespace

bool install_seccomp_filter() {
#if defined(__x86_64__)
  // Classic-BPF program (verified by the kernel). Instructions:
  //   0: load arch          1: jeq x86_64   -> 3 / else 2
  //   2: unknown arch       -> ALLOW (graceful degradation on other ABIs)
  //   3: load syscall nr    4: jeq __NR_socket -> 6 / else 5
  //   5: not socket()       -> ALLOW
  //   6: load args[0]       7: jeq AF_INET   -> 9 / else 8
  //   8: jeq AF_INET6       -> 10 / else 11
  //   9,10: KILL            11: ALLOW
  sock_filter prog[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 4),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, static_cast<std::uint32_t>(kArg0Offset)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, kAfInet, 1, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, kAfInet6, 1, 2),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  sock_fprog fprog = {
      static_cast<unsigned short>(sizeof(prog) / sizeof(prog[0])),
      prog,
  };

  // PR_SET_NO_NEW_PRIVS is mandatory before loading a filter as a non-root
  // process; it also makes the filter irreversible.
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    std::fprintf(stderr, "WARNING: prctl(PR_SET_NO_NEW_PRIVS) failed: "
                         "seccomp filter not installed\n");
    return false;
  }
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog) != 0) {
    std::fprintf(stderr, "WARNING: prctl(PR_SET_SECCOMP) failed: "
                         "seccomp filter not installed\n");
    return false;
  }
  return true;
#else
  // Architecture not covered by this hand-written filter; keep the app
  // functional (the compile-time no_network_symbols check still applies).
  return true;
#endif
}

}  // namespace security
