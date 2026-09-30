# Encrypt (C++)

Aplicación de escritorio (Linux) para cifrar/descifrar texto plano con
Argon2id + XChaCha20-Poly1305, 100% offline/airgapped. Equivalente en C++ de la
[app Android de referencia](../Encrypt-apk/README.md): mismo esquema
criptográfico, mismo sobre Base64, sin pistas en los errores de autenticación.

![Licencia](https://img.shields.io/badge/License-Apache--2.0-yellow.svg)

- Sin red: build reproducible con dependencias vendored (`third_party/`).
- Sin escritura automática a disco: ni estado de ventana, ni caches de shaders,
  ni core dumps. El único archivo que se crea es el sobre `.txt` que el usuario
  exporta/importa explícitamente con el diálogo de archivo (nombre y ubicación
  elegidos por él).
- Filtro seccomp a nivel de syscall que impide sockets AF_INET/AF_INET6.
- Material sensible en memoria mlock'ed, auto-zeroed (RAII en todo camino).
- Pepper opcional que nunca se serializa.
- Sobre Base64 URL-safe, autodocumentado (lleva sus parámetros KDF como AAD).

## Esquema criptográfico

| Componente | Elección |
|---|---|
| Cifrado | XChaCha20-Poly1305 (libsodium `crypto_aead_xchacha20poly1305_ietf`) |
| KDF | Argon2id (`crypto_pwhash`, `p = 1` fijo) |
| Pepper | No entra al KDF: se enlaza con BLAKE2b keyed (`crypto_generichash`) |
| Salt / Nonce | 16 / 24 bytes de `randombytes_buf` por operación |
| AAD | `v`, `aead`, `kdf`, `ops`, `mem_kib` van autenticados en el tag |

### Perfiles de fuerza

| Perfil | `ops` (iteraciones) | `mem_kib` |
|---|---|---|
| Estándar | 3 | 65536 (64 MiB) |
| Máxima | 6 | 262144 (256 MiB) |

No son los `OPSLIMIT_MODERATE`/`MEMLIMIT_MODERATE` de libsodium, que serían
3 y 256 MiB pero no 64: los valores 64/256 MiB están fijados para que el perfil
sea idéntico bit a bit al de la app Android y los sobres sean intercambiables.

## Requisitos

- CMake ≥ 3.20, un compilador C++20 (GCC ≥ 10 o clang ≥ 12), pkg-config, make.
- libsodium y Dear ImGui: **ya vendored**, no se descargan.
- GLFW3, X11 y OpenGL (dev headers) del sistema: `pkg-config glfw3 x11`.
- `ulimit -l unlimited` recomendado (los buffers se bloquean en RAM con mlock).
- `clang-tidy` (opcional, `ENCRYPT_ENABLE_CLANG_TIDY` viene en `ON`) y
  `clang-format` con la config del repo (`.clang-tidy`, `.clang-format`).

## Build y tests

```sh
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
./build/encrypt_app            # GUI (puede usarse con xvfb-run)
```

Opciones de CMake relevantes: `ENCRYPT_BUILD_TESTS` (`ON`),
`ENCRYPT_BUILD_FUZZERS` (`OFF`, requiere clang), `ENCRYPT_ENABLE_CLANG_TIDY`
(`ON`).

### Qué cubre `ctest`

| Test | Qué comprueba |
|---|---|
| `encrypt_tests` | Suite de auto-test del core criptográfico (round-trip, vectores, AAD, pepper) |
| `file_io_tests` | Lectura/escritura de sobres en disco, casos de error |
| `no_network_symbols` | Que el binario no enlace símbolos de red |
| `no_sensitive_test_strings_in_binary` | Que no se filtren secretos en el binario |
| `crypto_layer_has_no_imgui` | Que `encrypt_core` (`secure_mem` + `crypto`) no dependa de la GUI |

Los tres últimos son guardas de invariantes, no tests de comportamiento.
`scripts/e2e_gui_test.sh` cubre además un humo end-to-end de la GUI.

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
  ui/                 # app (estado) + screens cifrar/descifrar
  clipboard/          # portapapeles X11 seguro (auto-clear)
  security/           # seccomp-BPF (bloquea sockets de red)
tests/
  fuzz/               # targets libFuzzer
scripts/              # guardas de invariantes + e2e GUI (CTest)
third_party/          # libsodium + Dear ImGui (vendored)
```

El core (`encrypt_core` = `secure_mem` + `crypto`) es 100% independiente de la
GUI: se compila y se testea aislado (CTest `crypto_layer_has_no_imgui`).

## Documentación

- `SECURITY.md` — modelo de seguridad, formato del sobre, políticas de error.

## Licencia

Apache-2.0 — ver [LICENSE](LICENSE).
