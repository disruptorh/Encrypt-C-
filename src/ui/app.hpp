#ifndef ENCRYPT_UI_APP_HPP_
#define ENCRYPT_UI_APP_HPP_

#include <cstddef>
#include <cstdint>
#include <string>

#include "clipboard/secure_clipboard.hpp"
#include "crypto/kdf.hpp"
#include "secure_mem/secure_buffer.hpp"

namespace ui {

// Global application state. All sensitive material lives in mlock'ed,
// auto-zeroed secure buffers; the destructor and reset() wipe everything.
//
// Two screens (encrypt / decrypt) share the same editing buffers: switching
// modes wipes passwords and outputs but KEEPS the pepper (so a pepper marked
// at encrypt time is offered again at decrypt time, as the spec requires:
// "se le pide si el usuario lo marcó al cifrar").
class app {
 public:
  app() = default;
  ~app();

  app(const app&) = delete;
  app& operator=(const app&) = delete;

  // Initialize the secure clipboard (no X server -> clipboard disabled, app
  // still runs). Returns true unless a fatal initialization error occurred.
  bool init();
  void shutdown();

  // Render one frame of the active screen.
  void frame();

  // Last error message from the most recent operation (empty on success).
  const std::string& last_error() const { return last_error_; }

 private:
  enum class mode { encrypt, decrypt };
  mode mode_ = mode::encrypt;

  // Editing buffers (NUL-terminated, secure_mem-backed; lengths are kept in
  // sync by the ImGui edit callbacks).
  secure_mem::secure_string password_;
  secure_mem::secure_string confirm_;
  secure_mem::secure_string pepper_;
  secure_mem::secure_string plaintext_;
  secure_mem::secure_string envelope_input_;

  // Output material (secure, wiped on reset/mode switch/destructor).
  secure_mem::secure_string envelope_output_;
  secure_mem::secure_string plaintext_output_;
  secure_mem::secure_string kdf_salt_b64_;

  bool use_pepper_ = false;
  bool profile_maximum_ = false;

  std::string last_error_;
  std::string status_;

  clipboard::secure_clipboard clipboard_;

  struct copy_state {
    bool active = false;
    std::uint64_t expires_at_ms = 0;
  };
  copy_state copy_output_;

  static constexpr std::size_t kPasswordCapacity = 512;
  static constexpr std::size_t kPepperCapacity = 512;
  static constexpr std::size_t kPlaintextCapacity = 64 * 1024;
  static constexpr std::size_t kEnvelopeInputCapacity = 1024 * 1024;
  static constexpr std::uint64_t kClipboardTimeoutMs =
      clipboard::secure_clipboard::kDefaultTimeoutMs;

  void render_encrypt_screen();
  void render_decrypt_screen();
  void render_mode_switch();
  void render_copy_status(copy_state& item, std::uint64_t now);
  void begin_copy(copy_state& target, const char* text, std::size_t len,
                  std::uint64_t now);
  void poll_copies(std::uint64_t now);
  void do_encrypt();
  void do_decrypt();
  void switch_mode(mode next);
  void clear_outputs();
  void reset();

  static std::uint64_t now_ms();
};

}  // namespace ui

#endif  // ENCRYPT_UI_APP_HPP_
