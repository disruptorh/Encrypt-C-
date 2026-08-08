# Script: check_no_network.cmake
# Verifies that the built binary does not reference internet-capable symbols.
# Local IPC (X11/GLFW/GL) is acceptable and whitelisted; anything that could
# open a network connection or spawn a shell is a failure.
#
# Invoked by CTest as:
#   cmake -DBIN=... -DSCRIPT_DIR=... -P check_no_network.cmake

if(NOT EXISTS "${BIN}")
  message(FATAL_ERROR "binary not found: ${BIN}")
endif()

execute_process(
  COMMAND nm -D "${BIN}"
  OUTPUT_VARIABLE NM_OUTPUT
  ERROR_VARIABLE NM_ERROR
  RESULT_VARIABLE NM_RESULT
)

if(NOT NM_RESULT EQUAL 0)
  message(FATAL_ERROR "nm failed: ${NM_ERROR}")
endif()

# Symbols that enable network I/O, DNS resolution, shell execution or dynamic
# code loading. Anything in this list is a hard failure for an airgapped tool.
# Both defined and undefined (imported) symbols are checked, so vendored code
# cannot smuggle these primitives into the dynamic symbol table.
# (X11/GLFW/OpenGL are linked as shared libraries, so their internal use of
# local IPC does not place these symbols in OUR binary's dynamic table.)
set(FORBIDDEN
  socket
  connect
  bind
  listen
  accept
  send
  recv
  shutdown
  getaddrinfo
  getnameinfo
  gethostbyname
  gethostbyaddr
  inet_pton
  inet_ntop
  inet_addr
  ntohs
  htons
  sendto
  recvfrom
  connectx
  dlopen
  dlsym
  dlclose
  system
  popen
  execve
  execvp
  execl
  fork
  vfork
  posix_spawn
  waitpid
  __syslog
  syslog
  ifaddrs
  getifaddrs
)

set(failures 0)
foreach(sym IN LISTS FORBIDDEN)
  if(NM_OUTPUT MATCHES "[^_A-Za-z0-9]${sym}($|[^A-Za-z0-9_])")
    message(FATAL_ERROR "FAIL: binary references forbidden symbol '${sym}'")
  endif()
endforeach()

message(STATUS "OK: no forbidden (network/exec/dlopen) symbols found in ${BIN}")
