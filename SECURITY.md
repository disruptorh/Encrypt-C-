# Modelo de seguridad — Encrypt (C++)

Objetivo: cifrado/descifrado local de texto plano, 100% offline, con el mismo
perfil de seguridad que la app Android de referencia (Argon2id + XChaCha20-
Poly1305 + pepper), adaptado a C++ y con garantías de memoria fuerte.

## Criptografía

- **KDF**: Argon2id vía libsodium `crypto_pwhash_*`.
  - Perfil Estándar: 64 MiB / 3 pasadas (paridad con la versión Kotlin).
  - Perfil Máxima: 256 MiB / 6 pasadas (paridad con la versión Kotlin).
  - El perfil se guarda *dentro* del sobre y además se autentica vía AAD.
- **AEAD**: XChaCha20-Poly1305-IETF (`crypto_aead_xchacha20poly1305_ietf`),
  nonce de 24 bytes generado con CSPRNG, etiqueta Poly1305 incluida en el
  sobre.
- **Pepper**: secreto opcional que NO se serializa. Se liga a la clave final
  mediante un esquema tipo HMAC documentado en `crypto/kdf.hpp`:
  `final_key = BLAKE2b(key = BLAKE2b(pepper)[:32], msg = Argon2id(password, salt))`.
  Un pepper incorrecto produce exactamente el mismo fallo de autenticación que
  una contraseña incorrecta o un sobre manipulado.

## Formato del sobre

```
Base64 URL-safe sin padding de un JSON:
{
  "v": 1,
  "aead": "xchacha20poly1305_ietf",
  "kdf": "argon2id",
  "ops": <t_cost>,
  "mem_kib": <m_cost>,
  "salt": "<b64 16B>",
  "nonce": "<b64 24B>",
  "ciphertext": "<b64: cifrado || tag Poly1305>"
}
```

Los parámetros KDF viajan dentro del sobre y además son **AAD** de la AEAD
(`"v|aead|kdf|ops|mem_kib"`). Manipular `mem_kib`/`ops`/`v` en el JSON sin
re-cifrar invalida la autenticación; el receptor jamás deriva con parámetros
distintos de los originales (ver `engine_tampered_*_rejected_via_aad`).

## Mensaje de error de autenticación

Un solo mensaje genérico:
`"Fallo de autenticación: contraseña o campo secreto incorrectos, o datos manipulados."`
No distingue entre contraseña mala, pepper malo o blob manipulado (paridad con
la versión Kotlin; no da pistas al atacante).

## Memoria sensible

- Toda clave, contraseña, pepper y texto plano vive en `secure_mem::buffer` /
  `secure_mem::secure_string` (sodium_malloc + sodium_mlock + guard pages).
- Zeroización automática por RAII en TODOS los caminos de salida, incluidas
  excepciones (el equivalente C++ al `try/finally` de Kotlin).
- Los buffers son move-only: copiar material secreto es imposible por
  construcción.
- Si `sodium_mlock` falla (RLIMIT_MEMLOCK bajo) el código lanza en lugar de
  seguir con memoria swappeable. En desarrollo se usa `ulimit -l unlimited`.

## Airgap (compilación)

- Sin red: build reproducible con dependencias vendored en `third_party/`
  (libsodium, Dear ImGui). El build no descarga nada.
- `scripts/check_no_network.cmake` (CTest `no_network_symbols`): escanea la
  tabla de símbolos del binario con `nm -D` y falla si aparece cualquier
  símbolo de red/DNS/exec/dlopen (`socket`, `connect`, `getaddrinfo`, `system`,
  `fork`, `dlopen`, ...).
- `scripts/check_no_sensitive_strings.cmake` (CTest): tras un run de tests,
  escanea el binario de la app con `strings` y falla si contiene valores de
  test conocidos (contraseñas/peppers/plaintexts).
- `scripts/check_crypto_no_imgui.cmake` (CTest): la capa crypto/secure_mem no
  puede referenciar Dear ImGui (compila y se testea aislada).
- Dear ImGui se compila con `IMGUI_DISABLE_DEFAULT_SHELL_FUNCTIONS` (sin
  "open in shell" → sin fork/execvp de ImGui) y el loader de OpenGL usa
  `glfwGetProcAddress` en vez de `dlopen`.

## Airgap (runtime)

- `security/seccomp.cpp`: filtro seccomp-BPF que bloquea `socket(AF_INET)` /
  `socket(AF_INET6)` a nivel de syscall (cubre el vector de un LD_PRELOAD o una
  libGL maliciosa). `AF_UNIX` queda permitido para el display local.
- `main.cpp`: se desactivan core dumps (`RLIMIT_CORE=0`) y los shader caches en
  disco de Mesa/NVIDIA; ImGui no persiste estado (`IniFilename=nullptr`).
- Portapapeles seguro (`clipboard/secure_clipboard.cpp`): el texto sensible
  vive en memoria mlock'ed propia y solo se sirve ante peticiones de selección
  X11; se borra tras un timeout (30 s por defecto), al cambiar de pantalla o
  cuando otra app reclama la selección (`SelectionClear`).
  - **Copiado normal con una sola propiedad**: las copias pequeñas (Ctrl+C en
    un campo de texto, "Copiar texto descifrado") se sirven con un único
    `XChangeProperty`, el mecanismo estándar de cualquier portapapeles Linux.
    Los errores X11 benignos sobre ventanas de otro proceso
    (BadWindow/BadAtom) se ignoran para que un pegado concurrente nunca aborte
    la aplicación.
  - **El sobre cifrado NO se exporta por portapapeles.** Para no depender de
    las limitaciones y comportamientos variables del X11 (tamaño de propiedad,
    INCR de otros clientes), el sobre se exporta escribiendo un archivo `.txt`
    en la ubicación y con el nombre que el usuario elige mediante un diálogo
    integrado (`src/ui/file_dialog.cpp`, sin helpers externos ni `fork`).
  - **Pegado seguro**: `request_paste()` lee la selección actual para traer
    texto largo al interior de la app (botones "Pegar desde el portapapeles").
    Si el dueño externo negocia el protocolo INCR (contenido > ~256 KB), el
    pegado se cancela limpiamente y se informa al usuario de que use un
    fragmento menor o un archivo.
  - **Importación por archivo**: "Cargar sobre desde archivo (.txt)" lee el
    sobre directamente desde disco (límite 1 MiB, coherencia con la capacidad
    del campo de edición) en los buffers mlock'ed de edición.

## Presupuesto de memoria

`crypto::check_size_budget` replica la política Kotlin (`checkSizeBudget`):
pico estimado = 48 MiB base + memoria KDF + 10× texto; si supera el 90% de la
RAM del sistema se rechaza la operación (fail-open solo si no se puede medir).
Evita que un sobre malicioso con `mem_kib` extremo agote la RAM, además del
rango duro del parser (`kMemKibMax = 256 MiB`, `kOpsMax = 16`).

## Pruebas

- Unitarias (incluye roundtrip, pepper malo, password mala, sobre manipulado,
  parámetros KDF manipulados, plaintext binario, presupuesto de memoria).
- Determinismo de zeroización con `-Wl,--wrap=sodium_malloc/--wrap=sodium_free`
  (`test_secure_mem`).
- Fuzzing del parser de sobres con libFuzzer + ASan/UBSan
  (`tests/fuzz/fuzz_envelope_from_base64.cpp`, `ENCRYPT_BUILD_FUZZERS=ON`).
- clang-tidy (checks `cert-*`, `bugprone-*`, `clang-analyzer-*`,
  `performance-*`, `readability-*`, `modernize-*`; warnings = errores).
