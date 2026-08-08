#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>

#include <sys/resource.h>

#include <GLFW/glfw3.h>
#include <sodium.h>

#include <imgui.h>

#include "backends/imgui_impl_glfw.h"
#include "backends/imgui_impl_opengl3.h"

#include "security/seccomp.hpp"
#include "ui/app.hpp"

namespace {

// Airgap hardening: never allow the process to dump core (avoids secrets
// leaking to disk via core dumps).
void disable_core_dumps() {
  const rlimit rl = {0, 0};
  (void)setrlimit(RLIMIT_CORE, &rl);
}

// No-persistence hardening: suppress the OpenGL driver's on-disk shader caches
// (Mesa, NVIDIA). Must run before any GL/GLFW call, hence setenv() here.
void disable_gpu_shader_caches() {
  (void)setenv("MESA_SHADER_CACHE_DISABLE", "1", 1);
  (void)setenv("MESA_GLSL_CACHE_DISABLE", "1", 1);
  (void)setenv("__GL_SHADER_DISK_CACHE", "0", 1);
}

void load_monospace_font(ImGuiIO& io) {
  const char* candidates[] = {
      "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
      "/usr/share/fonts/truetype/freefont/FreeMono.ttf",
      "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
  };
  for (const char* path : candidates) {
    ImFont* font = io.Fonts->AddFontFromFileTTF(path, 18.0f);
    if (font != nullptr) {
      io.Fonts->Build();
      io.FontDefault = font;
      return;
    }
  }
}

}  // namespace

int main() {
  disable_core_dumps();
  disable_gpu_shader_caches();

  // Runtime syscall filter: blocks AF_INET/AF_INET6 socket() at the kernel
  // level (LD_PRELOAD / shared-library vector). Installed before any GL/X11
  // initialization. AF_UNIX stays allowed for the local display server.
  (void)security::install_seccomp_filter();

  if (sodium_init() < 0) {
    std::fprintf(stderr, "FATAL: libsodium failed to initialize\n");
    return 1;
  }

  if (!glfwInit()) {
    std::fprintf(stderr, "FATAL: GLFW failed to initialize\n");
    return 1;
  }

  glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
  glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
  glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);

  // Test seam (not used in production): ENCRYPT_SMOKE_MS exits the event loop
  // cleanly after the given number of milliseconds so CI/valgrind can exercise
  // the full init->frame->teardown path and report a trustworthy leak summary.
  const char* smoke_env = std::getenv("ENCRYPT_SMOKE_MS");
  const double smoke_ms =
      (smoke_env != nullptr) ? static_cast<double>(std::atof(smoke_env)) : 0.0;

  GLFWwindow* window =
      glfwCreateWindow(860, 720, "Encrypt - Cifrador local (Airgapped)",
                       nullptr, nullptr);
  if (window == nullptr) {
    std::fprintf(stderr, "FATAL: could not create GLFW window\n");
    glfwTerminate();
    return 1;
  }
  glfwMakeContextCurrent(window);
  glfwSwapInterval(1);

  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO& io = ImGui::GetIO();
  io.IniFilename = nullptr;  // never persist window state to disk
  io.LogFilename = nullptr;  // never allow ImGui logging to disk
  io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
  ImGui::StyleColorsDark();
  ImGuiStyle& style = ImGui::GetStyle();
  style.WindowRounding = 6.0f;
  style.FrameRounding = 4.0f;
  style.ChildRounding = 4.0f;
  style.WindowPadding = ImVec2(16, 16);
  style.FramePadding = ImVec2(10, 6);
  style.ItemSpacing = ImVec2(8, 7);
  style.WindowTitleAlign = ImVec2(0.5f, 0.5f);
  style.WindowBorderSize = 1.0f;
  style.ScrollbarSize = 12.0f;
  load_monospace_font(io);

  if (!ImGui_ImplGlfw_InitForOpenGL(window, true)) {
    std::fprintf(stderr, "FATAL: ImGui GLFW backend init failed\n");
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    return 1;
  }
  if (!ImGui_ImplOpenGL3_Init("#version 130")) {
    std::fprintf(stderr, "FATAL: ImGui OpenGL3 backend init failed\n");
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    return 1;
  }

  ui::app app;
  if (!app.init()) {
    std::fprintf(stderr, "FATAL: %s\n", app.last_error().c_str());
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    return 1;
  }

  ImVec4 clear_color(0.06f, 0.07f, 0.09f, 1.00f);

  while (!glfwWindowShouldClose(window)) {
    glfwPollEvents();

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();

    app.frame();

    ImGui::Render();
    int display_w = 0;
    int display_h = 0;
    glfwGetFramebufferSize(window, &display_w, &display_h);
    glViewport(0, 0, display_w, display_h);
    glClearColor(clear_color.x, clear_color.y, clear_color.z, clear_color.w);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

    glfwSwapBuffers(window);

    if (smoke_ms > 0.0 && glfwGetTime() * 1000.0 >= smoke_ms) {
      break;
    }
  }

  app.shutdown();
  ImGui_ImplOpenGL3_Shutdown();
  ImGui_ImplGlfw_Shutdown();
  ImGui::DestroyContext();
  glfwDestroyWindow(window);
  glfwTerminate();
  return 0;
}
