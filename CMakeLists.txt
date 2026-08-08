# ============================================================================
# Encrypt (C++, airgapped) — cifrado/descifrado local de texto plano.
#
# Build reproducible SIN red (todo vendored en third_party/):
#   cmake -S . -B build
#   cmake --build build -j
#   ctest --test-dir build
# ============================================================================
cmake_minimum_required(VERSION 3.20)
project(encrypt_app VERSION 1.0.0 LANGUAGES C CXX)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(ENCRYPT_BUILD_TESTS "Build the self-test suite" ON)
option(ENCRYPT_BUILD_FUZZERS "Build libFuzzer targets (requires clang)" OFF)
option(ENCRYPT_ENABLE_CLANG_TIDY "Run clang-tidy checks on our sources" ON)

# ----------------------------------------------------------------------------
# Hardening (applied to every target of this project)
# ----------------------------------------------------------------------------
add_compile_options(-Wall -Wextra -Wpedantic -fstack-protector-strong)
if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_compile_definitions(_FORTIFY_SOURCE=2)
endif()
add_link_options(-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack)

# ----------------------------------------------------------------------------
# libsodium (vendored, compiled statically via autotools) — third_party/
# ----------------------------------------------------------------------------
include(ExternalProject)

set(LIBSODIUM_ROOT ${CMAKE_BINARY_DIR}/_deps/libsodium/prefix)
set(LIBSODIUM_LIB ${LIBSODIUM_ROOT}/lib/libsodium.a)
set(LIBSODIUM_INCLUDE ${LIBSODIUM_ROOT}/include)

find_program(NPROC NAMES nproc)
if(NPROC)
  execute_process(COMMAND ${NPROC} OUTPUT_VARIABLE ENCRYPT_JOBS)
  string(STRIP "${ENCRYPT_JOBS}" ENCRYPT_JOBS)
else()
  set(ENCRYPT_JOBS 4)
endif()

ExternalProject_Add(libsodium_ext
  PREFIX ${CMAKE_BINARY_DIR}/_deps/libsodium
  SOURCE_DIR ${CMAKE_SOURCE_DIR}/third_party/libsodium
  CONFIGURE_COMMAND ${CMAKE_SOURCE_DIR}/third_party/libsodium/configure
      --prefix=${LIBSODIUM_ROOT}
      --disable-shared
      --enable-static
      --disable-tests
  BUILD_COMMAND ${CMAKE_MAKE_PROGRAM} -j${ENCRYPT_JOBS}
  INSTALL_COMMAND ${CMAKE_MAKE_PROGRAM} install
  INSTALL_DIR ${LIBSODIUM_ROOT}
  BUILD_IN_SOURCE 0
  BUILD_BYPRODUCTS ${LIBSODIUM_LIB} ${LIBSODIUM_INCLUDE}/sodium.h
)

# ----------------------------------------------------------------------------
# Core (no GUI) static library: secure_mem + crypto.
# This library MUST NOT include any Dear ImGui header (checked by the
# crypto_no_imgui CTest). It is built and tested in isolation.
# ----------------------------------------------------------------------------
add_library(encrypt_core STATIC
  src/secure_mem/secure_buffer.hpp
  src/secure_mem/secure_buffer.cpp
  src/crypto/base64.hpp
  src/crypto/base64.cpp
  src/crypto/json.hpp
  src/crypto/json.cpp
  src/crypto/aead.hpp
  src/crypto/aead.cpp
  src/crypto/kdf.hpp
  src/crypto/kdf.cpp
  src/crypto/envelope.hpp
  src/crypto/envelope.cpp
  src/crypto/crypto_engine.hpp
  src/crypto/crypto_engine.cpp
)
target_include_directories(encrypt_core PUBLIC
  ${CMAKE_SOURCE_DIR}/src
  ${LIBSODIUM_INCLUDE}
)
target_include_directories(encrypt_core SYSTEM PUBLIC ${LIBSODIUM_INCLUDE})
target_link_libraries(encrypt_core PUBLIC ${LIBSODIUM_LIB} pthread)
add_dependencies(encrypt_core libsodium_ext)

# ----------------------------------------------------------------------------
# Application (Dear ImGui + GLFW + OpenGL3, same backend as the reference app)
# ----------------------------------------------------------------------------
find_package(OpenGL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(GLFW REQUIRED IMPORTED_TARGET glfw3)
pkg_check_modules(X11 REQUIRED IMPORTED_TARGET x11)

set(IMGUI_DIR ${CMAKE_SOURCE_DIR}/third_party/imgui)

add_executable(encrypt_app
  src/main.cpp
  src/clipboard/secure_clipboard.cpp
  src/clipboard/secure_clipboard.hpp
  src/security/seccomp.cpp
  src/security/seccomp.hpp
  src/ui/app.cpp
  src/ui/app.hpp
  src/ui/screen_encrypt.cpp
  src/ui/screen_decrypt.cpp
  ${IMGUI_DIR}/imgui.cpp
  ${IMGUI_DIR}/imgui_draw.cpp
  ${IMGUI_DIR}/imgui_tables.cpp
  ${IMGUI_DIR}/imgui_widgets.cpp
  ${IMGUI_DIR}/backends/imgui_impl_glfw.cpp
  ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
)
target_include_directories(encrypt_app PRIVATE
  ${IMGUI_DIR}
  ${IMGUI_DIR}/backends
)
# ImGui vendored and patched for the airgapped profile:
#  - IMGUI_DISABLE_DEFAULT_SHELL_FUNCTIONS removes the default "open in shell"
#    (fork/execvp) implementation.
#  - The GL loader resolves entry points through glfwGetProcAddress() instead
#    of dlopen() (see IMGL3W_DYNLOAD guard in imgui_impl_opengl3_loader.h).
target_compile_definitions(encrypt_app PRIVATE
  IMGUI_DISABLE_DEFAULT_SHELL_FUNCTIONS
)
target_link_libraries(encrypt_app PRIVATE
  encrypt_core
  OpenGL::GL
  PkgConfig::GLFW
  PkgConfig::X11
)

if(ENCRYPT_CLANG_TIDY_CMD)
  set_property(TARGET encrypt_core encrypt_app
               PROPERTY CXX_CLANG_TIDY "${ENCRYPT_CLANG_TIDY_CMD}")
endif()

# clang-tidy on our own sources (only the app+core, not vendored code and not
# the test harness). Applied per-target (encrypt_core + encrypt_app).
if(ENCRYPT_ENABLE_CLANG_TIDY)
  find_program(CLANG_TIDY_BIN clang-tidy)
  if(CLANG_TIDY_BIN)
    set(ENCRYPT_CLANG_TIDY_CMD
        ${CLANG_TIDY_BIN}
        --config-file=${CMAKE_SOURCE_DIR}/.clang-tidy)
  endif()
endif()

# ----------------------------------------------------------------------------
# Tests
# ----------------------------------------------------------------------------
if(ENCRYPT_BUILD_TESTS)
  enable_testing()

  add_executable(encrypt_tests
    tests/test_main.cpp
    tests/test_secure_mem.cpp
    tests/test_aead.cpp
    tests/test_kdf.cpp
    tests/test_envelope.cpp
    tests/test_crypto_engine.cpp
  )
  target_include_directories(encrypt_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/tests
  )
  target_link_libraries(encrypt_tests PRIVATE encrypt_core)
  # Deterministic zeroization check: intercept sodium_malloc/sodium_free, and
  # force deterministic mlock failures (ASan makes RLIMIT_MEMLOCK unreliable).
  target_link_options(encrypt_tests PRIVATE
    "-Wl,--wrap=sodium_malloc,--wrap=sodium_free,--wrap=sodium_mlock")

  add_test(NAME encrypt_tests COMMAND encrypt_tests)

  add_test(
    NAME no_network_symbols
    COMMAND ${CMAKE_COMMAND}
      -DBIN=$<TARGET_FILE:encrypt_app>
      -DSCRIPT_DIR=${CMAKE_SOURCE_DIR}/scripts
      -P ${CMAKE_SOURCE_DIR}/scripts/check_no_network.cmake
  )

  add_test(
    NAME no_sensitive_test_strings_in_binary
    COMMAND ${CMAKE_COMMAND}
      -DBIN=$<TARGET_FILE:encrypt_app>
      -DSCRIPT_DIR=${CMAKE_SOURCE_DIR}/scripts
      -P ${CMAKE_SOURCE_DIR}/scripts/check_no_sensitive_strings.cmake
  )

  add_test(
    NAME crypto_layer_has_no_imgui
    COMMAND ${CMAKE_COMMAND}
      -DSRC_DIR=${CMAKE_SOURCE_DIR}/src
      -P ${CMAKE_SOURCE_DIR}/scripts/check_crypto_no_imgui.cmake
  )
endif()

# ----------------------------------------------------------------------------
# Fuzzing (libFuzzer + ASan/UBSan). Requires clang.
# ----------------------------------------------------------------------------
if(ENCRYPT_BUILD_FUZZERS)
  add_executable(envelope_from_base64_fuzzer
    tests/fuzz/fuzz_envelope_from_base64.cpp
  )
  target_include_directories(envelope_from_base64_fuzzer PRIVATE
    ${CMAKE_SOURCE_DIR}/tests
  )
  target_link_libraries(envelope_from_base64_fuzzer PRIVATE encrypt_core)
  target_compile_options(envelope_from_base64_fuzzer PRIVATE
    -fsanitize=fuzzer,address,undefined -g -O1 -fno-omit-frame-pointer)
  target_link_options(envelope_from_base64_fuzzer PRIVATE
    -fsanitize=fuzzer,address,undefined -g)
endif()
