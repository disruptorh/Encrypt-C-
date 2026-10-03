# Encrypt (C++)

Aplicación de escritorio (Linux) para cifrar/descifrar texto plano con
Argon2id + XChaCha20-Poly1305, 100% offline/airgapped. Equivalente en C++ de la
[app Android de referencia](../Encrypt-apk/README.md): mismo esquema
criptográfico, mismo sobre Base64, sin pistas en los errores de autenticación.

<p align="center">
  <a href="https://github.com/disruptorh/Encrypt-C-/releases/latest/download/Encrypt">
    <img alt="Descargar" src="https://img.shields.io/badge/%E2%AC%87%20Download-latest%20release-2f6feb?style=for-the-badge&logo=github&logoColor=white">
  </a>
  <a href="https://github.com/disruptorh/Encrypt-C-/releases/latest">
    <img alt="Versiones" src="https://img.shields.io/github/v/release/disruptorh/Encrypt-C-?label=release&style=flat&logo=github&logoColor=white">
  </a>
  <a href="./LICENSE">
    <img alt="Licencia" src="https://img.shields.io/badge/licencia-Apache--2.0-blue?style=flat">
  </a>
</p>

## 📥 Descarga rápida

El botón de arriba descarga el asset `Encrypt` de la release más reciente
publicada: un ejecutable **Linux x86-64 sin extensión de fichero**. Ojo al
nombre: el asset se llama `Encrypt` con mayúscula, mientras que el binario que
produce el build local se llama `encrypt_app` en minúsculas.

Para usarlo desde una terminal, o para fijarte en una versión concreta:

```bash
curl -L -o Encrypt https://github.com/disruptorh/Encrypt-C-/releases/latest/download/Encrypt && chmod +x Encrypt && ./Encrypt
```

No es un binario estático: enlaza dinámicamente contra `libOpenGL.so.0`,
`libglfw.so.3` y `libX11.so.6`. En Debian/Ubuntu se resuelven con:

```bash
sudo apt update && sudo apt install -y libopengl-dev libglfw3-dev libx11-dev libgl1
```

Para ejecutarlo sin pantalla (CI, contenedores, SSH sin X11):

```bash
sudo apt install -y xvfb && xvfb-run -a ./Encrypt
```

## 🚀 Uso rápido

1. Elige la pestaña **Cifrar** o **Descifrar**.
2. En **Cifrar**, escribe la contraseña, el texto plano y — opcionalmente — un
   *pepper*. Elige el perfil: *Perfil Estándar (64 MiB, 3 pasadas)* o *Perfil
   Máxima (256 MiB, 6 pasadas)*.
3. Pulsa **Cifrar** y exporta el sobre con **Guardar sobre en archivo (.txt)**. El
   sobre cifrado **no** sale por el portapapeles: se guarda con el diálogo de
   archivo integrado, con el nombre y la ubicación que tú elijas.
4. En **Descifrar**, marca *Usar pepper* si lo usaste al cifrar, pega la contraseña
   y el sobre (o usa **Cargar sobre desde archivo (.txt)**) y pulsa **Descifrar**.
   **Copiar texto descifrado** sí pasa por el portapapeles, con auto-clear a los
   30 s.

Si la contraseña, el pepper o los datos están manipulados, la app devuelve un
único mensaje genérico, sin distinguir cuál de las tres cosas falló.

## 📦 Compilar desde código

### Requisitos

- CMake ≥ 3.20, compilador C++20 (GCC ≥ 10 o clang ≥ 12), pkg-config, make.
- Sistema: development headers de GLFW3, X11 y OpenGL.
- Opcionales: `clang-tidy` (activo por defecto), `clang`, `valgrind`, `xvfb`.

### Clonar

Este repo **no tiene submódulos**: las dos dependencias están versionadas dentro
del propio repositorio, así que un `git clone` normal basta.

```bash
# 1. Clonar el repositorio
git clone https://github.com/disruptorh/Encrypt-C-.git
cd Encrypt-C--
```

### Dependencias

**Ya vendored en el repo, no hay que instalarlas** (el build no descarga nada de
la red; ver `third_party/VENDORED.md`):

| Dependencia | Dónde vive | Nota |
|---|---|---|
| libsodium 1.0.22 | `third_party/libsodium` | se compila estático vía autotools (`ExternalProject`) |
| Dear ImGui | `third_party/imgui` | parcheado para el perfil airgapped |

**Hay que instalarlas del sistema** (son las que pide el `CMakeLists.txt` vía
`find_package(OpenGL)` y `pkg_check_modules(glfw3, x11)`):

| Paquete Debian/Ubuntu | Para qué lo pide CMake |
|---|---|
| `build-essential` | g++, make |
| `cmake` | el propio build |
| `pkg-config` | `pkg_check_modules` |
| `libglfw3-dev` | `glfw3` (ventana, contexto GL, portapapeles) |
| `libx11-dev` | `x11` (portapapeles y display) |
| `libopengl-dev` | `find_package(OpenGL)` → `OpenGL::GL` |
| `libgl-dev` | cabeceras y `libGL.so` de Mesa |

```bash
# 2. Instalar las dependencias de compilación (Debian/Ubuntu)
sudo apt update && sudo apt install -y build-essential cmake pkg-config libglfw3-dev libx11-dev libopengl-dev libgl-dev
```

Para los chequeos estáticos (`ENCRYPT_ENABLE_CLANG_TIDY` viene en `ON`; si no
encuentra `clang-tidy` simplemente los salta):

```bash
# 2b. Herramientas de análisis estático (Debian/Ubuntu)
sudo apt update && sudo apt install -y clang-tidy clang-format
```

### Compilar

```bash
# 3. Configurar y compilar
cmake -S . -B build && cmake --build build -j
```

El ejecutable queda **directamente en `build/`**: `./build/encrypt_app`. Nada de
`build/Release/`. La primera build tarda bastante más que las siguientes, porque
libsodium se compila con autotools como `ExternalProject`.

### Ejecutar los tests

```bash
# 4. Suite de tests (requiere el binario ya compilado)
ctest --test-dir build --output-on-failure
```

| Target CTest | Qué comprueba |
|---|---|
| `encrypt_tests` | Suite de auto-test del core criptográfico: round-trip, vectores, AAD, pepper, presupuesto de memoria |
| `file_io_tests` | Lectura/escritura de sobres en disco y casos de error del diálogo |
| `no_network_symbols` | `nm -D` sobre el binario: no enlace símbolos de red/DNS/exec/`dlopen` |
| `no_sensitive_test_strings_in_binary` | `strings` sobre el binario: no contiene las contraseñas/peppers/textos de los tests |
| `crypto_layer_has_no_imgui` | La capa `encrypt_core` (`secure_mem` + `crypto`) no referencia Dear ImGui |

`encrypt_tests` se compila con
`-Wl,--wrap=sodium_malloc,--wrap=sodium_free,--wrap=sodium_mlock` para poder
comprobar de forma determinista que la zeroización ocurre. Los tres últimos no
son tests de comportamiento: son guardas de invariantes sobre el binario y las
fuentes.

### Ejecutar la aplicación

```bash
# 5. Lanzar la GUI
./build/encrypt_app
```

La app usa `mlock` y, si `sodium_mlock` falla por un `RLIMIT_MEMLOCK` bajo,
**lanza excepción en vez de seguir con memoria swappeable**. Devuelve el límite
a `unlimited` antes de lanzar la app:

```bash
# 6. Recomendado: sin límite de memoria bloqueada
ulimit -l unlimited && ./build/encrypt_app
```

## 🧰 Comandos útiles / Opciones

Opciones de CMake:

| Opción | Por defecto | Qué hace |
|---|---|---|
| `ENCRYPT_BUILD_TESTS` | `ON` | Compila `encrypt_tests` y `file_io_tests` y registra los tests de CTest |
| `ENCRYPT_ENABLE_CLANG_TIDY` | `ON` | Aplica `clang-tidy` con el `.clang-tidy` del repo sobre `encrypt_core` y `encrypt_app` (se salta si no está instalado) |
| `ENCRYPT_BUILD_FUZZERS` | `OFF` | Añade el target libFuzzer `envelope_from_base64_fuzzer` (requiere clang) |
| `CMAKE_BUILD_TYPE` | `Release` | Se fuerza a `Release` si no lo pasas |

```bash
# Build sin suite de tests ni clang-tidy (más rápido)
cmake -S . -B build -DENCRYPT_BUILD_TESTS=OFF -DENCRYPT_ENABLE_CLANG_TIDY=OFF && cmake --build build -j
```

Variables de entorno que la app lee:

| Variable | Por defecto | Efecto |
|---|---|---|
| `ENCRYPT_CLIPBOARD_TIMEOUT_MS` | `30000` | Milisegundos hasta el auto-clear del portapapeles |
| `ENCRYPT_SMOKE_MS` | `0` | *Test seam*: cierra el bucle de eventos tras N ms, para CI y valgrind |

### Builds especializados

```bash
# ASan + UBSan (Debug) y sus tests
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" && cmake --build build-asan -j && ctest --test-dir build-asan --output-on-failure
```

```bash
# Valgrind sobre los tests del core (no necesitan X, así que no hay clipboard)
valgrind --leak-check=full --error-exitcode=1 ./build-asan/encrypt_tests
```

```bash
# Fuzzing del parser de sobres (necesita clang + libFuzzer)
cmake -S . -B build-fuzz -DENCRYPT_BUILD_FUZZERS=ON -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_COMPILER=clang && cmake --build build-fuzz --target envelope_from_base64_fuzzer -j && ./build-fuzz/envelope_from_base64_fuzzer -max_total_time=300
```

Hay semillas de fuzzing ya versionadas en `tests/fuzz/seeds/`, incluida
`valid_envelope.base64`.

### Test end-to-end de la GUI

`scripts/e2e_gui_test.sh` cubre el round-trip completo con la app real: cifra,
relanza, selecciona "Descifrar", pega y comprueba que el texto descifrado es
byte a byte idéntico al original, que el portapapeles se auto-limpia y que no se
persiste nada bajo `$HOME`.

Necesita tres herramientas que **no** son dependencias de compilación:

```bash
# Instalar las herramientas del e2e de GUI (Debian/Ubuntu)
sudo apt update && sudo apt install -y xvfb xdotool xclip
```

```bash
# Ejecutar el e2e de la GUI (desde la raíz del repo, con la app ya compilada)
scripts/e2e_gui_test.sh
```

Para un humo rápido de la GUI sin navegar por ella:

```bash
# Humo: abrir y cerrar la ventana limpiamente tras 1,5 s
ENCRYPT_SMOKE_MS=1500 xvfb-run -a ./build/encrypt_app
```

## 🗂️ Estructura del proyecto

```text
.
├── CMakeLists.txt          # targets, vendored, guardas de CTest
├── .clang-tidy             # checks cert-*, bugprone-*, clang-analyzer-*, modernize-*
├── .clang-format
├── SECURITY.md             # modelo de seguridad, formato del sobre, políticas de error
├── scripts/
│   ├── check_no_network.cmake            # nm -D: sin símbolos de red/exec/dlopen
│   ├── check_no_sensitive_strings.cmake  # strings: sin secretos de test compilados
│   ├── check_crypto_no_imgui.cmake       # el core no puede referenciar ImGui
│   └── e2e_gui_test.sh                   # round-trip cifrar/descifrar con Xvfb
├── src/
│   ├── main.cpp            # init GLFW/ImGui, hardening de runtime
│   ├── crypto/             # base64, json (estricto), aead, kdf, envelope, engine
│   ├── secure_mem/         # buffer mlock'ed + secure_string
│   ├── ui/                 # app (estado), file_io, file_dialog, screens cifrar/descifrar
│   ├── clipboard/          # portapapeles X11 seguro (auto-clear)
│   └── security/           # seccomp-BPF (bloquea sockets de red)
├── tests/
│   └── fuzz/               # target libFuzzer + semillas en fuzz/seeds/
└── third_party/            # libsodium + Dear ImGui (vendored, ver VENDORED.md)
```

El core (`encrypt_core` = `secure_mem` + `crypto`) es 100% independiente de la
GUI: se compila y se testea aislado (CTest `crypto_layer_has_no_imgui`).

## 🔐 Seguridad

El detalle completo está en [SECURITY.md](SECURITY.md). Resumen de lo que
importa:

### Esquema criptográfico

| Componente | Elección |
|---|---|
| Cifrado | XChaCha20-Poly1305 (libsodium `crypto_aead_xchacha20poly1305_ietf`) |
| KDF | Argon2id (`crypto_pwhash`, `p = 1` fijo) |
| Pepper | No entra al KDF: se enlaza con BLAKE2b keyed (`crypto_generichash`) |
| Salt / Nonce | 16 / 24 bytes de `randombytes_buf` por operación |
| AAD | `v`, `aead`, `kdf`, `ops`, `mem_kib` van autenticados en el tag |

Perfiles de fuerza:

| Perfil | `ops` (iteraciones) | `mem_kib` |
|---|---|---|
| Estándar | 3 | 65536 (64 MiB) |
| Máxima | 6 | 262144 (256 MiB) |

No son los `OPSLIMIT_MODERATE`/`MEMLIMIT_MODERATE` de libsodium, que serían
3 y 256 MiB pero no 64: los valores 64/256 MiB están fijados para que el perfil
sea idéntico bit a bit al de la app Android y los sobres sean intercambiables.

### Memory handling

- Toda clave, contraseña, pepper y texto plano vive en `secure_mem::buffer` /
  `secure_mem::secure_string` (sodium_malloc + sodium_mlock + guard pages).
- Zeroización automática por RAII en todos los caminos de salida, incluidas las
  excepciones.
- Los buffers son move-only: copiar material secreto es imposible por
  construcción.
- Si `sodium_mlock` falla, el código lanza en vez de seguir con memoria
  swappeable.

### Airegap

Tres capas: el build no descarga nada (todo vendored), un filtro seccomp-BPF en
`src/security/seccomp.cpp` bloquea `socket(AF_INET)`/`socket(AF_INET6)` a nivel
de syscall (`AF_UNIX` queda permitido para el display local), y dos tests de
CTest auditan el binario. Si el kernel rechaza el filtro, la app **arranca
igual** (fail-open) y avisa por stderr.

Compilación: Dear ImGui con `IMGUI_DISABLE_DEFAULT_SHELL_FUNCTIONS` (sin "open
in shell", sin `fork`/`execvp`) y loader de OpenGL con `glfwGetProcAddress` en
vez de `dlopen()`.

### Sin escritura automática a disco

Ni estado de ventana de ImGui, ni caches de shaders, ni core dumps
(`RLIMIT_CORE=0`). El único archivo que se crea es el sobre `.txt` que el usuario
exporta o importa explícitamente con el diálogo integrado (`src/ui/file_dialog.cpp`,
sin helpers externos ni `fork`). El límite de importación es 1 MiB.

### Presupuesto de memoria

`crypto::check_size_budget` rechaza la operación si el pico estimado (48 MiB
base + memoria KDF + 10× el texto) supera el 90% de la RAM del sistema. El parser
tiene además un rango duro: `kMemKibMax = 256 MiB`, `kOpsMax = 16`.

### Endurecimiento de compilación

Todos los targets se compilan con `-Wall -Wextra -Wpedantic
-fstack-protector-strong`, `_FORTIFY_SOURCE=2` (salvo en `Debug`) y las opciones
de enlace `-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack`. `clang-tidy` corre con
`cert-*`, `bugprone-*`, `clang-analyzer-*`, `performance-*`, `readability-*` y
`modernize-*`, con warnings como errores.

## 📄 Licencia

Apache-2.0 (ver `LICENSE`). Las dependencias vendored conservan sus propias
licencias: libsodium 1.0.22 (ISC) y Dear ImGui (MIT).