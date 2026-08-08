#include "ui/app.hpp"

#include <cstring>

#include <imgui.h>

namespace ui {

// Screen 2: descifrar. Contraseña (+ pepper opcional, si se usó al cifrar),
// el sobre Base64 pegado y el texto plano resultante con su botón de copia.
void app::render_decrypt_screen() {
  const ImGuiViewport* vp = ImGui::GetMainViewport();
  ImGui::SetNextWindowPos(vp->WorkPos, ImGuiCond_Always);
  ImGui::SetNextWindowSize(vp->WorkSize, ImGuiCond_Always);

  if (ImGui::Begin("Encrypt - Descifrador local (airgapped)", nullptr,
                   ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
                       ImGuiWindowFlags_NoCollapse)) {
    render_mode_switch();

    ImGui::TextWrapped(
        "Pega un sobre cifrado con esta aplicación. La derivación de clave se "
        "hace con los parámetros autenticados que viajan dentro del sobre.");
    ImGui::Spacing();

    ImGui::TextUnformatted("Contraseña:");
    if (ImGui::InputText("##password_dec", password_.data(),
                         static_cast<int>(password_.capacity()),
                         ImGuiInputTextFlags_Password)) {
      password_.set_len(std::strlen(password_.data()));
    }

    ImGui::Spacing();
    if (ImGui::Checkbox(
            "Usar pepper (márcalo si lo usaste al cifrar)", &use_pepper_)) {
      if (!use_pepper_) pepper_.wipe();
    }
    if (use_pepper_) {
      if (ImGui::InputText("##pepper_dec", pepper_.data(),
                           static_cast<int>(pepper_.capacity()),
                           ImGuiInputTextFlags_Password)) {
        pepper_.set_len(std::strlen(pepper_.data()));
      }
      ImGui::TextDisabled(
          "Si el pepper no coincide con el del cifrado, el descifrado "
          "fallará con un error de autenticación genérico.");
    }

    ImGui::Spacing();
    ImGui::TextUnformatted("Sobre (Base64 URL-safe):");
    if (ImGui::InputTextMultiline(
            "##envelope_dec", envelope_input_.data(),
            static_cast<int>(envelope_input_.capacity()), ImVec2(-1, 180))) {
      envelope_input_.set_len(std::strlen(envelope_input_.data()));
    }

    ImGui::Spacing();
    if (ImGui::Button("Descifrar##dec", ImVec2(-1, 0))) {
      do_decrypt();
    }

    if (!last_error_.empty()) {
      ImGui::TextColored(ImVec4(0.95f, 0.35f, 0.35f, 1.0f), "%s",
                         last_error_.c_str());
    }
    if (!status_.empty()) {
      ImGui::TextColored(ImVec4(0.42f, 0.88f, 0.52f, 1.0f), "%s",
                         status_.c_str());
    }

    if (plaintext_output_.size() != 0) {
      ImGui::Spacing();
      ImGui::Separator();
      ImGui::TextUnformatted("Texto descifrado:");
      if (ImGui::BeginChild("plaintext_display", ImVec2(0, 180),
                            ImGuiChildFlags_Border,
                            ImGuiWindowFlags_HorizontalScrollbar)) {
        ImGui::TextWrapped("%.*s", static_cast<int>(plaintext_output_.size()),
                           plaintext_output_.data());
      }
      ImGui::EndChild();
      const std::uint64_t now = now_ms();
      if (ImGui::Button("Copiar texto descifrado", ImVec2(-1, 0))) {
        begin_copy(copy_output_, plaintext_output_.data(),
                   plaintext_output_.size(), now);
      }
      render_copy_status(copy_output_, now);
    }
  }
  ImGui::End();
}

}  // namespace ui
