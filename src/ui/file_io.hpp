#ifndef ENCRYPT_UI_FILE_IO_HPP_
#define ENCRYPT_UI_FILE_IO_HPP_

#include <cstddef>
#include <string>
#include <vector>

// File I/O used by the app's save/load dialog (Export sobre .txt). Kept free of
// ImGui/X11 so the logic is unit-testable in isolation. All writes use 0600
// permissions and refuse to overwrite existing files.
namespace ui::file_io {

struct file_entry {
  std::string name;
  bool is_dir = false;
};

// Suggested default name for an exported envelope, e.g. "sobre_20260901_123456.txt".
std::string default_export_filename();

// List `dir` (sorted: directories first, then files, case-insensitive).
// `out` is cleared first. Returns false and sets `*error` on failure.
bool list_directory(const std::string& dir, std::vector<file_entry>& out,
                    std::string* error);

// Validate and normalize a save file name (trim, reject "." / ".." / path
// separators, append ".txt" if missing). Returns false and sets `*error`.
bool sanitize_save_name(const std::string& raw, std::string* normalized,
                        std::string* error);

// Write `data[0..len)` to `path` with 0600 permissions, refusing to overwrite
// an existing file (O_CREAT|O_EXCL). Returns false and sets `*error` on any
// failure (including "already exists").
bool write_text_file(const std::string& path, const char* data, std::size_t len,
                     std::string* error);

// Read the whole contents of `path` into `out`, trimming trailing blank lines,
// failing if the file exceeds `max_bytes`. Returns false and sets `*error` on
// any failure (including "empty file").
bool read_text_file(const std::string& path, std::size_t max_bytes,
                    std::string* out, std::string* error);

}  // namespace ui::file_io

#endif  // ENCRYPT_UI_FILE_IO_HPP_