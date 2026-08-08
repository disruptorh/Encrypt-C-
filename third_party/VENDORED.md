# third_party: dependencias vendored (build 100% offline)

Todas las dependencias del proyecto están vendored en este directorio y se
compilan como parte del build. El build **no descarga nada**: ni en configuración
ni en compilación. Cada árbol incluye su propia licencia.

## libsodium

- Directorio: `third_party/libsodium/`
- Upstream: https://github.com/jedisct1/libsodium
- Versión: **1.0.22** (`1.0.22-RELEASE`)
- Commit aguas arriba: `77e1ce5d` ("Add code comments about why variable-time is fine for public inputs")
- Licencia: ISC (`LICENSE` dentro del árbol).
- Build: autotools vía `ExternalProject` (estático, `--disable-shared
  --disable-tests`). Mismo procedimiento que la app de referencia BIP-39.
- Comprobación de integridad del árbol vendored (SHA-256, fichero completo):

```
sha256sum third_party/libsodium/src/libsodium/sodium/utils.c
```

## Dear ImGui

- Directorio: `third_party/imgui/`
- Upstream: https://github.com/ocornut/imgui
- Versión: **1.91.9** (`IMGUI_VERSION "1.91.9"`)
- Commit aguas arriba: `e241b2e80`
- Licencia: MIT (`LICENSE.txt` dentro del árbol).
- Uso: fuente compilada directamente en el target de la app (sin submodulo, sin
  descarga). Backend GLFW + OpenGL3.
- No se utiliza el loader dinámico de OpenGL: se compila con
  `IMGUI_DISABLE_DEFAULT_SHELL_FUNCTIONS` y el backend OpenGL3 resuelve sus
  símbolos vía `glfwGetProcAddress()` (ver `imgui_impl_opengl3_loader.h`),
  evitando `dlopen`.
