#include "ui/app.hpp"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <exception>

#include <imgui.h>

#include "crypto/crypto_engine.hpp"

namespace ui {

std::uint64_t app::now_ms() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

app::~app() { shutdown(); }

bool app::init() {
  // Route ImGui's copy callback (Ctrl+C in a text field) through the secure,
  // auto-clearing clipboard so accidental copies are also protected. The paste
  // callback (Ctrl+V) is deliberately left to the GLFW backend: it is
  // synchronous, whereas X11 selection reads are asynchronous (and INCR
  // transfers are multi-roundtrip). Long-content pasting is provided by the
  // explicit "Pegar desde el portapapeles" buttons, which use the asynchronous
  // secure read path and land directly in the mlock'ed editing buffers.
  ImGuiIO& io = ImGui::GetIO();
  io.SetClipboardTextFn = &app::set_clipboard_callback;
  io.ClipboardUserData = this;

  // Pre-grow the editing buffers once so ImGui never triggers a reallocation
  // of a locked buffer mid-edit (reallocation would move locked pages).
  password_.reserve(kPasswordCapacity);
  confirm_.reserve(kPasswordCapacity);
  pepper_.reserve(kPepperCapacity);
  plaintext_.reserve(kPlaintextCapacity);
  envelope_input_.reserve(kEnvelopeInputCapacity);

  if (!clipboard_.init()) {
    last_error_ =
        "No hay servidor X disponible; el portapapeles estará desactivado.";
  } else {
    // Optional auto-clear override (ms), e.g. for testing. Default 30 s.
    if (const char* env = std::getenv("ENCRYPT_CLIPBOARD_TIMEOUT_MS")) {
      const long v = std::strtol(env, nullptr, 10);
      if (v > 0) clipboard_.set_timeout_ms(static_cast<std::uint64_t>(v));
    }
  }
  return true;
}

void app::shutdown() {
  clipboard_.shutdown();
  password_.wipe();
  confirm_.wipe();
  pepper_.wipe();
  plaintext_.wipe();
  envelope_input_.wipe();
  envelope_output_.wipe();
  plaintext_output_.wipe();
  kdf_salt_b64_.wipe();
  paste_target_ = nullptr;
}

void app::frame() {
  const std::uint64_t now = now_ms();
  clipboard_.poll(now);
  poll_paste(now);
  poll_copies(now);
  if (mode_ == mode::encrypt) {
    render_encrypt_screen();
  } else {
    render_decrypt_screen();
  }
  render_file_dialog();
}

void app::render_mode_switch() {
  ImGui::TextUnformatted("Modo:");
  ImGui::SameLine();
  if (ImGui::RadioButton("Cifrar", mode_ == mode::encrypt)) {
    switch_mode(mode::encrypt);
  }
  ImGui::SameLine();
  if (ImGui::RadioButton("Descifrar", mode_ == mode::decrypt)) {
    switch_mode(mode::decrypt);
  }
  ImGui::Separator();
  ImGui::Spacing();
}

void app::switch_mode(mode next) {
  if (next == mode_) return;
  // Passwords and outputs are wiped on the mode switch. The pepper survives:
  // a pepper marked at encrypt time is re-offered at decrypt time.
  password_.wipe();
  confirm_.wipe();
  clear_outputs();
  dialog_close();
  last_error_.clear();
  status_.clear();
  mode_ = next;
}

void app::clear_outputs() {
  envelope_output_.wipe();
  plaintext_output_.wipe();
  kdf_salt_b64_.wipe();
  copy_output_.active = false;
}

void app::begin_copy(copy_state& target, const char* text, std::size_t len,
                     std::uint64_t now) {
  // The secure clipboard holds exactly one value; only the latest copy is
  // shown as active so the indicator never lies about what is stored.
  copy_output_.active = false;
  last_error_.clear();
  status_.clear();
  if (clipboard_.set_text(text, len)) {
    target.active = true;
    target.expires_at_ms = now + clipboard_.timeout_ms();
    status_ = "Copiado. El portapapeles se autolimpia en unos segundos.";
  } else if (clipboard_.is_active()) {
    target.active = false;
    last_error_ =
        "El contenido supera el límite del portapapeles del sistema "
        "(8 MiB). Cópialo en menos fragmentos o guarda el archivo.";
  } else {
    target.active = false;
    last_error_ = "No hay servidor X; no se pudo copiar.";
  }
}

// ImGui callback: called for Ctrl+C / Ctrl+X from a text field. `user_data` is
// the app instance (set via io.ClipboardUserData). Redirect to the secure,
// auto-clearing clipboard so accidental copies are also protected.
void app::set_clipboard_callback(void* user_data, const char* text) {
  if (user_data == nullptr || text == nullptr) return;
  app* self = static_cast<app*>(user_data);
  self->begin_copy(self->copy_output_, text, std::strlen(text), now_ms());
}

// Paste-from-X11 into a target secure string (used by the "Pegar" buttons).
void app::paste_into(secure_mem::secure_string* target) {
  last_error_.clear();
  status_.clear();
  paste_target_ = nullptr;
  if (!clipboard_.is_active()) {
    last_error_ = "No hay servidor X; no se pudo pegar.";
    return;
  }
  if (clipboard_.is_pasting()) {
    paste_target_ = target;
    status_ = "Recibiendo del portapapeles...";
    return;
  }
  if (!clipboard_.request_paste()) {
    last_error_ =
        "El portapapeles está vacío o el dueño no respondió; inténtalo de "
        "nuevo.";
    return;
  }
  paste_target_ = target;
  status_ = "Recibiendo del portapapeles...";
}

// Called every frame: if a paste request has completed, deliver the data to
// the target secure string set by paste_into().
void app::poll_paste(std::uint64_t /*now*/) {
  if (paste_target_ == nullptr) return;
  if (!clipboard_.is_active() || clipboard_.is_pasting()) return;
  std::size_t len = 0;
  const char* data = clipboard_.paste(len);
  if (data == nullptr) {
    last_error_ =
        "No se pudo leer del portapapeles. Si el contenido es muy grande, "
        "pégalo en partes.";
    status_.clear();
    paste_target_ = nullptr;
    return;
  }
  paste_target_->assign(data, len);
  status_ = "Pegado.";
  last_error_.clear();
  paste_target_ = nullptr;
}

void app::poll_copies(std::uint64_t now) {
  if (copy_output_.active && now >= copy_output_.expires_at_ms) {
    copy_output_.active = false;
  }
}

void app::render_copy_status(copy_state& item, std::uint64_t now) {
  if (item.active) {
    const std::uint64_t remaining =
        (item.expires_at_ms > now) ? item.expires_at_ms - now : 0;
    ImGui::TextColored(ImVec4(0.42f, 0.88f, 0.52f, 1.0f),
                       "En el portapapeles por ~%llu s.",
                       static_cast<unsigned long long>(remaining / 1000));
  }
}

void app::do_encrypt() {
  last_error_.clear();
  status_.clear();
  clear_outputs();

  const char* pw = password_.data();
  const char* conf = confirm_.data();
  if (password_.size() == 0) {
    last_error_ = "La contraseña es obligatoria.";
    return;
  }
  if (password_.size() < 8) {
    last_error_ = "La contraseña debe tener al menos 8 caracteres.";
    return;
  }
  if (std::strcmp(pw, conf) != 0) {
    last_error_ = "Las contraseñas no coinciden.";
    return;
  }
  if (plaintext_.size() == 0) {
    last_error_ = "No hay texto que cifrar.";
    return;
  }

  const secure_mem::secure_string* pepper_ptr =
      (use_pepper_ && pepper_.size() != 0) ? &pepper_ : nullptr;

  try {
    const crypto::kdf_profile profile =
        profile_maximum_ ? crypto::kdf_maximum() : crypto::kdf_standard();
    // The engine takes a byte_buffer; build a locked copy of the plaintext.
    secure_mem::byte_buffer pt(plaintext_.size());
    if (plaintext_.size() != 0) {
      std::memcpy(pt.data(), plaintext_.data(), plaintext_.size());
    }
    const std::string b64 = crypto::encrypt(pt, password_, pepper_ptr, profile);
    envelope_output_.assign(b64.data(), b64.size());
    status_ =
        "Cifrado completado. Copia el sobre y borra el texto original de esta "
        "máquina.";
  } catch (const std::exception& e) {
    last_error_ = e.what();
    return;
  }

  // Wipe the transient plaintext after a successful encryption.
  plaintext_.wipe();
}

void app::do_decrypt() {
  last_error_.clear();
  status_.clear();
  plaintext_output_.wipe();
  copy_output_.active = false;

  if (envelope_input_.size() == 0) {
    last_error_ = "Pega un sobre para descifrarlo.";
    return;
  }
  if (password_.size() == 0) {
    last_error_ = "La contraseña es obligatoria.";
    return;
  }

  const secure_mem::secure_string* pepper_ptr =
      (use_pepper_ && pepper_.size() != 0) ? &pepper_ : nullptr;

  try {
    secure_mem::byte_buffer pt = crypto::decrypt(envelope_input_.data(),
                                                 password_, pepper_ptr);
    plaintext_output_.assign(reinterpret_cast<const char*>(pt.data()),
                             pt.size());
    status_ = "Descifrado correcto.";
  } catch (const std::exception& e) {
    last_error_ = e.what();
    return;
  }

  // Wipe the transient envelope input after a successful decryption.
  envelope_input_.wipe();
}

void app::reset() {
  clipboard_.clear_now();
  password_.wipe();
  confirm_.wipe();
  pepper_.wipe();
  plaintext_.wipe();
  envelope_input_.wipe();
  clear_outputs();
  dialog_close();
  use_pepper_ = false;
  profile_maximum_ = false;
  last_error_.clear();
  status_.clear();
}

}  // namespace ui
