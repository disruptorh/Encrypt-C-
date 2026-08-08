# Script: check_crypto_no_imgui.cmake
# Verifies the crypto/ + secure_mem/ layers are completely UI-agnostic: none of
# their source files may USE Dear ImGui (includes, symbols, namespace calls).
# Comments may mention "Dear ImGui" in prose, but `#include <imgui.h>`,
# `ImGui::` calls or `imgui_` identifiers are hard failures. This is a hard
# requirement of the architecture: the crypto core must compile and be tested
# in isolation.
#
# Invoked by CTest as:
#   cmake -DSRC_DIR=... -P check_crypto_no_imgui.cmake

file(GLOB_RECURSE CORE_SOURCES
  "${SRC_DIR}/crypto/*"
  "${SRC_DIR}/secure_mem/*"
)

foreach(f IN LISTS CORE_SOURCES)
  file(READ "${f}" CONTENT)
  # ImGui usage looks like one of: #include*imgui*, *ImGui::*, *imgui_*.
  # (A bare "imgui" word inside a comment is not usage.)
  set(line_no 1)
  string(REPLACE ";" "\\n" CONTENT_LINES "${CONTENT}")
  foreach(line IN LISTS CONTENT_LINES)
    if(line MATCHES "imgui_|ImGui::|#include[ \t]*[<\"][^>\"]*imgui")
      message(FATAL_ERROR
        "FAIL: ${f}:${line_no}: line uses Dear ImGui: ${line}")
    endif()
    math(EXPR line_no "${line_no} + 1")
  endforeach()
endforeach()

message(STATUS "OK: crypto/ and secure_mem/ have zero ImGui usage")
