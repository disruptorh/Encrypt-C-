# Encrypt (C++)

Aplicación de escritorio (Linux) para cifrar/descifrar texto plano con
Argon2id + XChaCha20-Poly1305, 100% offline/airgapped. Equivalente en C++ de la
app Android de referencia: mismo esquema criptográfico, mismo sobre Base64, sin
pistas en los errores de autenticación.

- Sin red: build reproducible con dependencias vendored (`third_party/`).
- Sin escritura a disco: ni estado de ventana, ni caches de shaders, ni core
  dumps.
- Filtro seccomp a nivel de syscall que impide sockets AF_INET/AF_INET6.
- Material sensible en memoria mlock'ed, auto-zeroed (RAII en todo camino).
- Pepper opcional que nunca se serializa.
- Sobre Base64 URL-safe, autodocumentado (lleva sus parámetros KDF como AAD).

## Requisitos

- CMake ≥ 3.20, un compilador C++20 (GCC ≥ 10 o clang ≥ 12), pkg-config, make.
- libsodium y Dear ImGui: **ya vendored**, no se descargan.
- GLFW3, X11 y OpenGL (dev headers) del sistema: `pkg-config glfw3 x11`.
- `ulimit -l unlimited` recomendado (los buffers se bloquean en RAM con mlock).

## Build y tests

```sh
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
./build/encrypt_app            # GUI (puede usarse con xvfb-run)
```

### Builds especializados

```sh
# ASan + UBSan (Debug)
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
cmake --build build-asan -j
ctest --test-dir build-asan --output-on-failure

# Valgrind (App: no X -> sin clipboard; core y tests cubren la app)
valgrind --leak-check=full --error-exitcode=1 ./build-asan/encrypt_tests

# Fuzzing del parser de sobres (clang + libFuzzer)
cmake -S . -B build-fuzz -DENCRYPT_BUILD_FUZZERS=ON \
      -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_COMPILER=clang
cmake --build build-fuzz --target envelope_from_base64_fuzzer -j
./build-fuzz/envelope_from_base64_fuzzer -max_total_time=300
```

### Humo de la GUI (sin pantalla)

```sh
ENCRYPT_SMOKE_MS=1500 xvfb-run -a ./build/encrypt_app
```

## Estructura

```
src/
  main.cpp            # init GLFW/ImGui, hardening de runtime
  crypto/             # base64, json (estricto), aead, kdf, envelope, engine
  secure_mem/         # buffer mlock'ed + secure_string
  ui/                 # app (estado) + pantallas cifrar/descifrar
  clipboard/          # portapapeles X11 seguro (auto-clear)
  security/           # seccomp-BPF (bloquea sockets de red)
tests/
  fuzz/               # targets libFuzzer
scripts/              # checks de airgap (CTest)
third_party/          # libsodium + Dear ImGui (vendored)
```

El core (`encrypt_core` = `secure_mem` + `crypto`) es 100% independiente de la
GUI: se compila y se testea aislado (CTest `crypto_layer_has_no_imgui`).

## Documentación

- `SECURITY.md` — modelo de seguridad, formato del sobre, políticas de error.
