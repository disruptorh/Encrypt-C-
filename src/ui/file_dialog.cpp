#include "ui/app.hpp"

#include <cstdio>
#include <filesystem>
#include <string>

#include <imgui.h>

#include "ui/file_io.hpp"

namespace ui {
namespace {

namespace fs = std::filesystem;

}  // namespace

void app::open_save_dialog(secure_mem::secure_string* payload) {
  file_dialog_.open = true;
  file_dialog_.save_mode = true;
  file_dialog_.payload = payload;
  file_dialog_.error.clear();
  file_dialog_.name = file_io::default_export_filename();
  file_dialog_.dir = fs::current_path().string();
  if (file_dialog_.dir.empty()) file_dialog_.dir = ".";
  file_dialog_.refresh = true;
  file_dialog_.focus_name = true;
}

void app::open_load_dialog(secure_mem::secure_string* target) {
  file_dialog_.open = true;
  file_dialog_.save_mode = false;
  file_dialog_.payload = target;
  file_dialog_.error.clear();
  file_dialog_.name.clear();
  file_dialog_.dir = fs::current_path().string();
  if (file_dialog_.dir.empty()) file_dialog_.dir = ".";
  file_dialog_.refresh = true;
  file_dialog_.focus_name = true;
}

void app::dialog_close() {
  file_dialog_.open = false;
  file_dialog_.payload = nullptr;
  file_dialog_.name.clear();
  file_dialog_.entries.clear();
  file_dialog_.is_dir.clear();
  file_dialog_.error.clear();
  file_dialog_.focus_name = false;
}

void app::refresh_file_dialog() {
  std::vector<file_io::file_entry> entries;
  std::string err;
  if (!file_io::list_directory(file_dialog_.dir, entries, &err)) {
    file_dialog_.entries.clear();
    file_dialog_.is_dir.clear();
    file_dialog_.error = err;
    file_dialog_.refresh = false;
    return;
  }
  file_dialog_.entries.clear();
  file_dialog_.is_dir.clear();
  file_dialog_.entries.reserve(entries.size());
  file_dialog_.is_dir.reserve(entries.size());
  for (const file_io::file_entry& e : entries) {
    file_dialog_.entries.push_back(e.name);
    file_dialog_.is_dir.push_back(e.is_dir);
  }
  file_dialog_.error.clear();
  file_dialog_.refresh = false;
}

void app::dialog_save() {
  file_dialog_.error.clear();
  if (file_dialog_.payload == nullptr || file_dialog_.payload->size() == 0) {
    file_dialog_.error = "No hay sobre que guardar.";
    return;
  }
  std::string normalized;
  if (!file_io::sanitize_save_name(file_dialog_.name, &normalized,
                                   &file_dialog_.error)) {
    return;
  }
  const std::string path = (fs::path(file_dialog_.dir) / normalized).string();
  if (!file_io::write_text_file(path, file_dialog_.payload->data(),
                                file_dialog_.payload->size(),
                                &file_dialog_.error)) {
    return;
  }
  status_ = "Sobre guardado en: " + path;
  last_error_.clear();
  dialog_close();
}

void app::dialog_load() {
  file_dialog_.error.clear();
  std::string name = file_dialog_.name;
  const std::size_t b = name.find_first_not_of(" \t\r\n");
  if (b == std::string::npos) {
    file_dialog_.error = "Selecciona un archivo de la lista.";
    return;
  }
  const std::size_t e = name.find_last_not_of(" \t\r\n");
  name = name.substr(b, e - b + 1);
  const std::string path = (fs::path(file_dialog_.dir) / name).string();
  std::string data;
  if (!file_io::read_text_file(path, kEnvelopeInputCapacity, &data,
                               &file_dialog_.error)) {
    return;
  }
  file_dialog_.payload->assign(data.data(), data.size());
  status_ = "Sobre cargado desde: " + path;
  last_error_.clear();
  dialog_close();
}

void app::render_file_dialog() {
  if (!file_dialog_.open) return;
  if (file_dialog_.refresh) refresh_file_dialog();

  const ImGuiViewport* vp = ImGui::GetMainViewport();
  ImGui::SetNextWindowPos(
      ImVec2(vp->WorkPos.x + (vp->WorkSize.x - 600) * 0.5f,
             vp->WorkPos.y + (vp->WorkSize.y - 430) * 0.5f),
      ImGuiCond_Always);
  ImGui::SetNextWindowSize(ImVec2(600, 430), ImGuiCond_Always);

  const char* title =
      file_dialog_.save_mode ? "Guardar sobre en archivo (.txt)"
                             : "Cargar sobre desde archivo (.txt)";
  if (ImGui::Begin(title, &file_dialog_.open,
                   ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
                       ImGuiWindowFlags_NoCollapse)) {
    ImGui::TextUnformatted("Carpeta:");
    ImGui::SameLine();
    ImGui::TextWrapped("%s", file_dialog_.dir.c_str());
    if (ImGui::Button("Subir un nivel##filedlg", ImVec2(-1, 0))) {
      fs::path p(file_dialog_.dir);
      fs::path parent = p.parent_path();
      if (!parent.empty() && parent != p) {
        file_dialog_.dir = parent.string();
        if (file_dialog_.dir.empty()) file_dialog_.dir = "/";
        file_dialog_.refresh = true;
      }
    }

    if (ImGui::BeginChild("##filedlg_list", ImVec2(0, 170),
                          ImGuiChildFlags_Border)) {
      for (std::size_t i = 0; i < file_dialog_.entries.size(); ++i) {
        const std::string& label = file_dialog_.entries[i];
        std::string full = label;
        if (file_dialog_.is_dir[i]) full += "/";
        const bool selected =
            (!file_dialog_.is_dir[i] && label == file_dialog_.name);
        if (ImGui::Selectable(full.c_str(), selected)) {
          if (file_dialog_.is_dir[i]) {
            fs::path p = (label == "..")
                             ? fs::path(file_dialog_.dir).parent_path()
                             : fs::path(file_dialog_.dir) / label;
            if (!p.empty()) {
              file_dialog_.dir = p.string();
              file_dialog_.refresh = true;
            }
          } else {
            file_dialog_.name = label;
          }
        }
      }
    }
    ImGui::EndChild();

    ImGui::TextUnformatted("Nombre de archivo:");
    char name_buf[512];
    std::snprintf(name_buf, sizeof(name_buf), "%s", file_dialog_.name.c_str());
    ImGui::SetNextItemWidth(-1);
    // Auto-focus the name field when the dialog opens so saving/loading is a
    // simple "type name, Enter" flow (and automatable by keyboard).
    if (file_dialog_.focus_name) {
      ImGui::SetKeyboardFocusHere();
      file_dialog_.focus_name = false;
    }
    if (ImGui::InputText("##filedlg_name", name_buf, sizeof(name_buf))) {
      file_dialog_.name = name_buf;
    }
    if (!file_dialog_.save_mode) {
      ImGui::TextDisabled("Selecciona un archivo .txt que contenga un sobre.");
    }

    if (!file_dialog_.error.empty()) {
      ImGui::TextColored(ImVec4(0.95f, 0.35f, 0.35f, 1.0f), "%s",
                         file_dialog_.error.c_str());
    }

    ImGui::Spacing();
    if (file_dialog_.save_mode) {
      if (ImGui::Button("Guardar##filedlg", ImVec2(-1, 0))) {
        dialog_save();
      }
    } else {
      if (ImGui::Button("Cargar##filedlg", ImVec2(-1, 0))) {
        dialog_load();
      }
    }
    if (ImGui::Button("Cancelar##filedlg", ImVec2(-1, 0))) {
      dialog_close();
    }
  }
  ImGui::End();
}

}  // namespace ui