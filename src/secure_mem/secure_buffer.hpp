#ifndef ENCRYPT_SECURE_MEM_SECURE_BUFFER_HPP_
#define ENCRYPT_SECURE_MEM_SECURE_BUFFER_HPP_

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <utility>

#include <sodium.h>

namespace secure_mem {

// ---------------------------------------------------------------------------
// RAII wrapper for sensitive memory (passwords, keys, plaintext, pepper).
//
// Contract (mirrors the reference BIP-39 app, with a stricter policy):
//  - Every allocation comes from sodium_malloc() + sodium_mlock(), so the
//    region is page-aligned, surrounded by guard pages (libsodium) and locked
//    into RAM. On destruction the memory is sodium_memzero()ed, munlock()ed
//    and sodium_free()d on every path (including exception paths).
//  - If sodium_mlock() fails (e.g. RLIMIT_MEMLOCK too low) the constructor
//    throws instead of continuing with swappable memory. The application must
//    try to raise RLIMIT_MEMLOCK in main() (documented dependency).
//  - Move-only: copies are impossible by construction, so secret material can
//    never be duplicated silently.
// ---------------------------------------------------------------------------
template <typename T>
class buffer {
 public:
  using value_type = T;

  buffer() = default;
  explicit buffer(std::size_t n) { allocate(n); }

  buffer(buffer&& other) noexcept : ptr_(other.ptr_), size_(other.size_) {
    other.ptr_ = nullptr;
    other.size_ = 0;
  }

  buffer& operator=(buffer&& other) noexcept {
    if (this != &other) {
      release();
      ptr_ = other.ptr_;
      size_ = other.size_;
      other.ptr_ = nullptr;
      other.size_ = 0;
    }
    return *this;
  }

  buffer(const buffer&) = delete;
  buffer& operator=(const buffer&) = delete;

  ~buffer() { release(); }

  // Reallocate to `n` elements. If `preserve` is false the new region is
  // zero-initialized; if true the first min(n, old) bytes are carried over.
  // A failed mlock leaves the allocation untouched and throws.
  void resize(std::size_t n, bool preserve = false) {
    if (n == size_) return;
    T* np = nullptr;
    if (n != 0) {
      void* raw = sodium_malloc(n * sizeof(T));
      if (raw == nullptr) throw std::bad_alloc();
      if (sodium_mlock(raw, n * sizeof(T)) != 0) {
        sodium_free(raw);
        throw std::runtime_error(
            "secure_mem: no se pudo bloquear memoria en RAM "
            "(sodium_mlock fallo); revisa ulimit -l");
      }
      np = static_cast<T*>(raw);
      if (preserve && ptr_ != nullptr) {
        const std::size_t keep = (n < size_) ? n : size_;
        std::memset(np, 0, n * sizeof(T));
        std::memcpy(np, ptr_, keep * sizeof(T));
      } else {
        std::memset(np, 0, n * sizeof(T));
      }
    }
    release();
    ptr_ = np;
    size_ = n;
  }

  // Zero the contents in place without releasing the allocation.
  void zero() noexcept {
    if (ptr_ != nullptr && size_ != 0) sodium_memzero(ptr_, size_ * sizeof(T));
  }

  // Zero and release the allocation (idempotent).
  void release_and_zero() noexcept { release(); }

  T* data() noexcept { return ptr_; }
  const T* data() const noexcept { return ptr_; }
  std::size_t size() const noexcept { return size_; }
  bool empty() const noexcept { return size_ == 0; }

 private:
  void release() noexcept {
    if (ptr_ != nullptr) {
      sodium_memzero(ptr_, size_ * sizeof(T));
      sodium_munlock(ptr_, size_ * sizeof(T));
      sodium_free(ptr_);
      ptr_ = nullptr;
      size_ = 0;
    }
  }

  void allocate(std::size_t n) { resize(n, /*preserve=*/false); }

  T* ptr_ = nullptr;
  std::size_t size_ = 0;
};

// Fixed-size byte buffer, the workhorse for keys/plaintext/ciphertext.
using byte_buffer = buffer<std::uint8_t>;

// Null-terminated mutable string backed by mlock'ed memory (same contract as
// the reference app). Used for passwords, pepper, and plaintext held by the
// UI. Deliberately does NOT expose std::string-like copying: no copy
// constructor/assignment, and data() is the only escape hatch. There is no
// `c_str()` accessor so the type cannot accidentally be copied into a
// std::string at the call site.
class secure_string {
 public:
  secure_string() { buf_.resize(1); }
  ~secure_string() { wipe(); }

  secure_string(secure_string&& other) noexcept
      : buf_(std::move(other.buf_)), len_(other.len_) {
    other.reset_to_empty();
  }

  secure_string& operator=(secure_string&& other) noexcept {
    if (this != &other) {
      buf_ = std::move(other.buf_);
      len_ = other.len_;
      other.reset_to_empty();
    }
    return *this;
  }

  secure_string(const secure_string&) = delete;
  secure_string& operator=(const secure_string&) = delete;

  void assign(const char* s, std::size_t n) {
    reserve(n);
    if (n != 0) std::memcpy(buf_.data(), s, n);
    buf_.data()[n] = '\0';
    len_ = n;
  }

  void assign(const char* s) { assign(s, std::strlen(s)); }

  void append(const char* s, std::size_t n) {
    const std::size_t old = len_;
    reserve(old + n);
    if (n != 0) std::memcpy(buf_.data() + old, s, n);
    buf_.data()[old + n] = '\0';
    len_ = old + n;
  }

  // Grow the backing buffer to hold `need` data bytes plus the NUL terminator,
  // preserving the current content. Doubling strategy matches the reference.
  void reserve(std::size_t need) {
    if (need + 1 <= buf_.size()) return;
    std::size_t cap = (buf_.size() != 0) ? buf_.size() * 2 : 64;
    while (cap < need + 1) cap *= 2;
    buf_.resize(cap, /*preserve=*/true);
  }

  void clear() noexcept {
    if (buf_.data() != nullptr) buf_.data()[0] = '\0';
    len_ = 0;
  }

  void wipe() noexcept {
    buf_.zero();
    len_ = 0;
  }

  char* data() noexcept { return buf_.data(); }
  const char* data() const noexcept { return buf_.data(); }

  // Called by the ImGui edit callbacks after the widget modified the buffer.
  void set_len(std::size_t n) noexcept { len_ = n; }

  std::size_t size() const noexcept { return len_; }
  std::size_t capacity() const noexcept { return buf_.size(); }
  bool empty() const noexcept { return len_ == 0; }

 private:
  // Called from the move ctor/assignment (noexcept): the backing buffer was
  // already moved away, so there is nothing to reset except the length. Doing
  // NO allocation here keeps the noexcept guarantee (an allocation in a
  // noexcept context would terminate). Subsequent use goes through reserve()/
  // assign(), which re-allocate as needed.
  void reset_to_empty() noexcept { len_ = 0; }

  buffer<char> buf_;
  std::size_t len_ = 0;
};

}  // namespace secure_mem

#endif  // ENCRYPT_SECURE_MEM_SECURE_BUFFER_HPP_
