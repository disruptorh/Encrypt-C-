#include "ui/app.hpp"

#include <cstring>

#include <imgui.h>

namespace ui {

// Screen 1: cifrar. Contraseña + confirmación, pepper opcional, texto a
// cifrar, perfil de KDF y el sobre resultante con su botón de copia. La
// ventana llena el viewport para escalar a contenedores airgapped pequeños.
void app::render_encrypt_screen() {
  const ImGuiViewport* vp = ImGui::GetMainViewport();
  ImGui::SetNextWindowPos(vp->WorkPos, ImGuiCond_Always);
  ImGui::SetNextWindowSize(vp->WorkSize, ImGuiCond_Always);

  if (ImGui::Begin("Encrypt - Cifrador local (airgapped)", nullptr,
                   ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
                       ImGuiWindowFlags_NoCollapse)) {
    render_mode_switch();

    ImGui::TextWrapped(
        "Todo se procesa localmente. El sobre Base64 contiene todo lo "
        "necesario para descifrar, menos tu contraseña y el pepper (si lo "
        "usas). Nada se escribe a disco.");
    ImGui::Spacing();

    ImGui::TextUnformatted("Contraseña:");
    if (ImGui::InputText("##password_enc", password_.data(),
                         static_cast<int>(password_.capacity()),
                         ImGuiInputTextFlags_Password)) {
      password_.set_len(std::strlen(password_.data()));
    }
    ImGui::TextUnformatted("Confirmar contraseña:");
    if (ImGui::InputText("##confirm_enc", confirm_.data(),
                         static_cast<int>(confirm_.capacity()),
                         ImGuiInputTextFlags_Password)) {
      confirm_.set_len(std::strlen(confirm_.data()));
    }

    ImGui::Spacing();
    if (ImGui::Checkbox("Usar pepper (frase adicional que deberás recordar)",
                        &use_pepper_)) {
      if (!use_pepper_) pepper_.wipe();
    }
    if (use_pepper_) {
      if (ImGui::InputText("##pepper_enc", pepper_.data(),
                           static_cast<int>(pepper_.capacity()),
                           ImGuiInputTextFlags_Password)) {
        pepper_.set_len(std::strlen(pepper_.data()));
      }
      ImGui::TextDisabled(
          "El pepper se mezcla en la derivación de clave; si lo olvidas, el "
          "sobre no se podrá descifrar.");
    }

    ImGui::Spacing();
    ImGui::TextUnformatted("Texto a cifrar:");
    if (ImGui::InputTextMultiline(
            "##plaintext_enc", plaintext_.data(),
            static_cast<int>(plaintext_.capacity()), ImVec2(-1, 180))) {
      plaintext_.set_len(std::strlen(plaintext_.data()));
    }

    ImGui::Spacing();
    const bool std_profile = !profile_maximum_;
    if (ImGui::RadioButton("Perfil Estándar (64 MiB, 3 pasadas)", std_profile)) {
      profile_maximum_ = false;
    }
    ImGui::SameLine();
    if (ImGui::RadioButton("Perfil Máxima (256 MiB, 6 pasadas)",
                           profile_maximum_)) {
      profile_maximum_ = true;
    }

    ImGui::Spacing();
    if (ImGui::Button("Cifrar##enc", ImVec2(-1, 0))) {
      do_encrypt();
    }

    if (!last_error_.empty()) {
      ImGui::TextColored(ImVec4(0.95f, 0.35f, 0.35f, 1.0f), "%s",
                         last_error_.c_str());
    }
    if (!status_.empty()) {
      ImGui::TextColored(ImVec4(0.42f, 0.88f, 0.52f, 1.0f), "%s",
                         status_.c_str());
    }

    if (envelope_output_.size() != 0) {
      ImGui::Spacing();
      ImGui::Separator();
      ImGui::TextUnformatted(
          "Sobre (cópialo y guárdalo fuera de esta máquina):");
      if (ImGui::BeginChild("envelope_display", ImVec2(0, 180),
                            ImGuiChildFlags_Border,
                            ImGuiWindowFlags_HorizontalScrollbar)) {
        ImGui::TextWrapped("%s", envelope_output_.data());
      }
      ImGui::EndChild();
      const std::uint64_t now = now_ms();
      if (ImGui::Button("Copiar sobre", ImVec2(-1, 0))) {
        begin_copy(copy_output_, envelope_output_.data(),
                   envelope_output_.size(), now);
      }
      render_copy_status(copy_output_, now);
    }
  }
  ImGui::End();
}

}  // namespace ui
