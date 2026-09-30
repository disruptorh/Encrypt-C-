#include "ui/file_io.hpp"

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>

#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

namespace ui::file_io {
namespace {

namespace fs = std::filesystem;

std::string trim(const std::string& s) {
  const std::size_t b = s.find_first_not_of(" \t\r\n");
  if (b == std::string::npos) return "";
  const std::size_t e = s.find_last_not_of(" \t\r\n");
  return s.substr(b, e - b + 1);
}

bool ends_with_icase(const std::string& s, const std::string& suffix) {
  if (s.size() < suffix.size()) return false;
  for (std::size_t i = 0; i < suffix.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(s[s.size() - suffix.size() + i])) !=
        std::tolower(static_cast<unsigned char>(suffix[i]))) {
      return false;
    }
  }
  return true;
}

}  // namespace

std::string default_export_filename() {
  const std::time_t t = std::time(nullptr);
  std::tm tmv{};
  localtime_r(&t, &tmv);
  char buf[64];
  std::snprintf(buf, sizeof(buf), "sobre_%04d%02d%02d_%02d%02d%02d.txt",
                tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday, tmv.tm_hour,
                tmv.tm_min, tmv.tm_sec);
  return buf;
}

bool list_directory(const std::string& dir, std::vector<file_entry>& out,
                    std::string* error) {
  out.clear();
  if (error != nullptr) error->clear();
  std::error_code ec;
  const fs::path d(dir);
  if (dir.empty() || !fs::is_directory(d, ec) || ec) {
    if (error != nullptr) *error = "No se puede acceder a: " + dir;
    return false;
  }
  // Parent entry first so the user can always navigate out.
  const fs::path parent = d.parent_path();
  if (!parent.empty() && parent != d) {
    out.push_back({parent.filename().string(), true});
  }

  std::vector<file_entry> list;
  for (fs::directory_iterator it(d, fs::directory_options::skip_permission_denied, ec),
       end;
       it != end; ++it) {
    if (ec) break;
    std::error_code ec2;
    const bool isd = it->is_directory(ec2) && !ec2;
    list.push_back({it->path().filename().string(), isd});
  }

  // Sort: directories first, then files, case-insensitive alphabetical.
  std::stable_sort(list.begin(), list.end(), [](const file_entry& a, const file_entry& b) {
    if (a.is_dir != b.is_dir) return a.is_dir > b.is_dir;
    std::string la = a.name;
    std::string lb = b.name;
    std::transform(la.begin(), la.end(), la.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    std::transform(lb.begin(), lb.end(), lb.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return la < lb;
  });

  out.insert(out.end(), list.begin(), list.end());
  return true;
}

bool sanitize_save_name(const std::string& raw, std::string* normalized,
                        std::string* error) {
  if (error != nullptr) error->clear();
  std::string name = trim(raw);
  if (name.empty()) {
    if (error != nullptr) *error = "Escribe un nombre de archivo.";
    return false;
  }
  if (name == "." || name == ".." || name.find('/') != std::string::npos ||
      name.find('\\') != std::string::npos) {
    if (error != nullptr) *error = "Nombre de archivo no válido.";
    return false;
  }
  if (!ends_with_icase(name, ".txt")) name += ".txt";
  if (normalized != nullptr) *normalized = name;
  return true;
}

bool write_text_file(const std::string& path, const char* data, std::size_t len,
                     std::string* error) {
  if (error != nullptr) error->clear();
  const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL
#if !defined(O_CLOEXEC)
                                         | 0
#else
                                         | O_CLOEXEC
#endif
                     ,
                       0600);
  if (fd < 0) {
    if (error != nullptr) {
      *error = (errno == EEXIST) ? "Ese archivo ya existe. Elige otro nombre."
                                 : std::string("No se pudo crear el archivo: ") +
                                       std::strerror(errno);
    }
    return false;
  }
  const char* p = data;
  std::size_t left = len;
  bool ok = true;
  int saved_errno = 0;
  while (left > 0) {
    const ssize_t w = ::write(fd, p, left);
    if (w < 0) {
      if (errno == EINTR) continue;
      saved_errno = errno;
      ok = false;
      break;
    }
    p += w;
    left -= static_cast<std::size_t>(w);
  }
  if (ok) {
    if (::fsync(fd) != 0) {
      saved_errno = errno;
      ok = false;
    }
  }
  ::close(fd);
  if (!ok) {
    ::unlink(path.c_str());
    if (error != nullptr) {
      *error = std::string("No se pudo escribir el archivo: ") +
               std::strerror(saved_errno);
    }
    return false;
  }
  return true;
}

bool read_text_file(const std::string& path, std::size_t max_bytes,
                    std::string* out, std::string* error) {
  if (error != nullptr) error->clear();
  const int fd = ::open(path.c_str(), O_RDONLY
#if !defined(O_CLOEXEC)
                                     | 0
#else
                                     | O_CLOEXEC
#endif
                     );
  if (fd < 0) {
    if (error != nullptr) {
      *error = std::string("No se pudo abrir el archivo: ") +
               std::strerror(errno);
    }
    return false;
  }
  std::string data;
  data.reserve(max_bytes + 1);
  char buf[8192];
  int saved_errno = 0;
  bool read_ok = true;
  for (;;) {
    const ssize_t n = ::read(fd, buf, sizeof(buf));
    if (n < 0) {
      if (errno == EINTR) continue;
      saved_errno = errno;
      read_ok = false;
      break;
    }
    if (n == 0) break;
    if (data.size() + static_cast<std::size_t>(n) > max_bytes) {
      read_ok = false;
      saved_errno = E2BIG;
      break;
    }
    data.append(buf, static_cast<std::size_t>(n));
  }
  ::close(fd);
  if (!read_ok) {
    if (error != nullptr) {
      *error = (saved_errno == E2BIG)
                   ? "El archivo supera 1 MiB. Recórtalo o pégalo en partes."
                   : std::string("Error al leer el archivo: ") +
                         std::strerror(saved_errno);
    }
    return false;
  }
  // Strip trailing blank lines so a trailing newline never breaks parsing.
  while (!data.empty() && (data.back() == '\n' || data.back() == '\r' ||
                           data.back() == ' ' || data.back() == '\t')) {
    data.pop_back();
  }
  if (data.empty()) {
    if (error != nullptr) *error = "El archivo está vacío.";
    return false;
  }
  *out = std::move(data);
  return true;
}

}  // namespace ui::file_io