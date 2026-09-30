#ifndef ENCRYPT_CLIPBOARD_SECURE_CLIPBOARD_HPP_
#define ENCRYPT_CLIPBOARD_SECURE_CLIPBOARD_HPP_

#include <cstddef>
#include <cstdint>

#include <X11/Xlib.h>

#include "secure_mem/secure_buffer.hpp"

namespace clipboard {

// Secure X11 clipboard (simple, normal selection owner).
//
// On copy, the sensitive text is stored in an mlock'ed, auto-zeroed buffer and
// served to other apps through the standard X11 CLIPBOARD selection using a
// single property write — the same mechanism any normal Linux clipboard uses
// (no INCR). On timeout (or explicit clear) ownership is released and the
// buffer is zeroed.
//
// On paste, the current selection is requested and read with a single
// GetWindowProperty; the result is delivered into an mlock'ed buffer. Content
// larger than the X server's request limit is not transferable this way; the
// app refuses the copy and reports the size instead of failing silently.
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
  // wiped first. The auto-clear timer is (re)started. Returns false (and keeps
  // the previous selection) if the content is beyond the single-property limit.
  bool set_text(const char* text, std::size_t len);

  // Request the current CLIPBOARD selection content from its owner. The result
  // is delivered asynchronously: poll() must be called until is_pasting() turns
  // false, then paste() returns the data. Returns false if the request could
  // not be initiated (no selection owner / clipboard disabled).
  bool request_paste();

  // Retrieve the pasted content after request_paste() completes. Returns a
  // pointer valid until the next set_text()/clear_now()/request_paste(). Sets
  // `out_len` to the byte length. Returns nullptr if no data is available.
  const char* paste(std::size_t& out_len);

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

  // True while a paste request is in flight and the data has not arrived yet.
  bool is_pasting() const { return paste_pending_; }

  // Largest single-property transfer supported (matches the X request limit).
  static constexpr std::uint64_t kDefaultTimeoutMs = 30'000;
  static constexpr std::size_t kMaxClipboardBytes = 8 * 1024 * 1024;

 private:
  void claim_selection();
  // ICCCM-recommended way to obtain the current X11 server timestamp (see
  // claim_selection). Returns CurrentTime only on timeout.
  ::Time current_server_time();
  void handle_event(XEvent& ev);
  void handle_selection_request(XEvent& ev);
  void handle_selection_clear();
  void handle_selection_notify(XEvent& ev);
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
  Atom incr_atom_ = 0;
  Atom paste_prop_atom_ = 0;

  // Write-side buffer (secure, auto-zeroed).
  secure_mem::byte_buffer buffer_;
  std::size_t len_ = 0;
  bool active_ = false;
  bool owned_ = false;
  std::uint64_t timeout_ms_ = kDefaultTimeoutMs;
  std::uint64_t expires_at_ms_ = 0;

  // Read-side result (secure, auto-zeroed).
  secure_mem::byte_buffer paste_buffer_;
  std::size_t paste_len_ = 0;
  bool paste_pending_ = false;
};

}  // namespace clipboard

#endif  // ENCRYPT_CLIPBOARD_SECURE_CLIPBOARD_HPP_