#ifndef ENCRYPT_CLIPBOARD_SECURE_CLIPBOARD_HPP_
#define ENCRYPT_CLIPBOARD_SECURE_CLIPBOARD_HPP_

#include <cstddef>
#include <cstdint>

#include <X11/Xlib.h>

#include "secure_mem/secure_buffer.hpp"

namespace clipboard {

// Secure X11 clipboard owner.
//
// The sensitive text is stored in mlock'ed, auto-zeroed memory owned by this
// object (it is never handed to GLFW or X, only served from the private buffer
// on selection requests). On timeout (or explicit clear) the ownership is
// released and the buffer is zeroed.
class secure_clipboard {
 public:
  secure_clipboard() = default;
  ~secure_clipboard() { shutdown(); }

  secure_clipboard(const secure_clipboard&) = delete;
  secure_clipboard& operator=(const secure_clipboard&) = delete;

  // Open an X11 connection and a hidden helper window. Returns false if no X
  // display is available (clipboard becomes a no-op).
  bool init();

  // Wipe the buffer, release selection ownership and close the X connection.
  void shutdown();

  // Publish `text` as the CLIPBOARD selection. Any previously held content is
  // wiped first. The auto-clear timer is (re)started.
  void set_text(const char* text, std::size_t len);

  // Wipe the buffer and clear the selection immediately.
  void clear_now();

  // Call once per frame: services selection requests and enforces the
  // auto-clear timeout. `now_ms` is a monotonically increasing time base.
  void poll(std::uint64_t now_ms);

  void set_timeout_ms(std::uint64_t ms) { timeout_ms_ = ms; }
  std::uint64_t timeout_ms() const { return timeout_ms_; }

  bool is_active() const { return active_; }
  bool is_owned() const { return owned_; }
  bool has_pending() const { return owned_ && len_ != 0; }
  std::uint64_t expires_at_ms() const { return expires_at_ms_; }

  static constexpr std::uint64_t kDefaultTimeoutMs = 30'000;

 private:
  void claim_selection();
  // ICCCM-recommended way to obtain the current X11 server timestamp (see
  // claim_selection). Returns CurrentTime only on timeout.
  ::Time current_server_time();
  void handle_event(XEvent& ev);
  void handle_selection_request(XEvent& ev);
  void handle_selection_clear();
  void respond_with_text(::Time timestamp, ::Window requestor, Atom property,
                         Atom target);
  void respond_with_targets(::Time timestamp, ::Window requestor, Atom property);

  Display* dpy_ = nullptr;
  Window win_ = 0;
  Atom clip_atom_ = 0;
  Atom utf8_atom_ = 0;
  Atom string_atom_ = 0;
  Atom text_atom_ = 0;
  Atom targets_atom_ = 0;
  Atom ts_atom_ = 0;

  secure_mem::byte_buffer buffer_;
  std::size_t len_ = 0;
  bool active_ = false;
  bool owned_ = false;
  std::uint64_t timeout_ms_ = kDefaultTimeoutMs;
  std::uint64_t expires_at_ms_ = 0;
};

}  // namespace clipboard

#endif  // ENCRYPT_CLIPBOARD_SECURE_CLIPBOARD_HPP_
