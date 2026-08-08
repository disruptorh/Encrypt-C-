// secure_buffer.cpp
//
// Implementation helpers for the secure_mem layer. The template <buffer<T>>
// and secure_string live in the header (templates must be visible to users);
// this translation unit holds the non-template support code.
//
// Dependencies documented here (enforced at runtime by the caller):
//  - sodium_init() must have run before any secure buffer is allocated.
//  - The process should raise RLIMIT_MEMLOCK as early as possible in main()
//    (best-effort, up to the hard limit), otherwise sodium_mlock() can fail
//    for large buffers and this layer throws a clear exception.
//  - setrlimit(RLIMIT_CORE, 0) must be called by main() so that a crash can
//    never dump mlock'ed secrets to disk (a core file is not affected by
//    sodium_memzero).
//
// There is intentionally no other logic here; keeping it trivial avoids
// accidental copies of secret material and keeps the crypto/ layer free of
// any dependency on the UI.
#include "secure_mem/secure_buffer.hpp"
