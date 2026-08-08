#include "crypto/json.hpp"

#include <cstdint>

namespace crypto::json {

namespace {

struct cursor {
  const char* p;
  const char* const end;

  bool at_end() const { return p >= end; }
  char peek() const {
    if (p >= end) throw parse_error("json: fin inesperado");
    return *p;
  }
  char next() {
    if (p >= end) throw parse_error("json: fin inesperado");
    return *p++;
  }
  void skip_ws() {
    while (p < end) {
      const char c = *p;
      if (c != ' ' && c != '\t' && c != '\n' && c != '\r') break;
      ++p;
    }
  }
};

std::uint32_t read_hex4(cursor& c) {
  std::uint32_t v = 0;
  for (int i = 0; i < 4; ++i) {
    const char ch = c.next();
    std::uint32_t d;
    if (ch >= '0' && ch <= '9') {
      d = static_cast<std::uint32_t>(ch - '0');
    } else if (ch >= 'a' && ch <= 'f') {
      d = static_cast<std::uint32_t>(ch - 'a' + 10);
    } else if (ch >= 'A' && ch <= 'F') {
      d = static_cast<std::uint32_t>(ch - 'A' + 10);
    } else {
      throw parse_error("json: secuencia \\u inválida");
    }
    v = (v << 4) | d;
  }
  return v;
}

void append_utf8(std::string& out, std::uint32_t cp) {
  if (cp < 0x80) {
    out.push_back(static_cast<char>(cp));
  } else if (cp < 0x800) {
    out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
  } else if (cp < 0x10000) {
    out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
  } else {
    out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
  }
}

std::string parse_string(cursor& c) {
  if (c.next() != '"') throw parse_error("json: se esperaba una cadena");
  std::string out;
  while (true) {
    const char ch = c.next();
    if (ch == '"') return out;
    if (ch == '\\') {
      const char esc = c.next();
      switch (esc) {
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case 'u': {
          std::uint32_t cp = read_hex4(c);
          if (cp >= 0xD800 && cp <= 0xDBFF) {
            // High surrogate: must be followed by \uXXXX low surrogate.
            if (c.next() != '\\' || c.next() != 'u') {
              throw parse_error("json: sustituto alto sin par");
            }
            const std::uint32_t lo = read_hex4(c);
            if (lo < 0xDC00 || lo > 0xDFFF) {
              throw parse_error("json: sustituto alto con par inválido");
            }
            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
          } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
            throw parse_error("json: sustituto bajo huérfano");
          }
          append_utf8(out, cp);
          break;
        }
        default:
          throw parse_error("json: escape inválido");
      }
    } else if (static_cast<unsigned char>(ch) < 0x20) {
      throw parse_error("json: carácter de control sin escapar");
    } else {
      out.push_back(ch);
    }
  }
}

long long parse_integer(cursor& c) {
  bool negative = false;
  if (c.peek() == '-') {
    negative = true;
    c.next();
  }
  if (c.at_end() || c.peek() < '0' || c.peek() > '9') {
    throw parse_error("json: entero inválido");
  }
  if (c.peek() == '0') {
    c.next();
    if (!c.at_end() && c.peek() >= '0' && c.peek() <= '9') {
      throw parse_error("json: cero con dígitos iniciales");
    }
    return 0;
  }
  long long v = 0;
  while (!c.at_end() && c.peek() >= '0' && c.peek() <= '9') {
    const int d = c.next() - '0';
    if (v > (9223372036854775807LL - d) / 10) {
      throw parse_error("json: entero desbordado");
    }
    v = v * 10 + d;
  }
  return negative ? -v : v;
}

}  // namespace

object parse_object(const char* s, std::size_t len) {
  cursor c{s, s + len};
  c.skip_ws();
  if (c.next() != '{') throw parse_error("json: se esperaba un objeto");

  object obj;
  c.skip_ws();
  if (!c.at_end() && c.peek() == '}') {
    c.next();
    c.skip_ws();
    if (!c.at_end()) throw parse_error("json: datos sobrantes tras el objeto");
    return obj;
  }

  while (true) {
    c.skip_ws();
    const std::string key = parse_string(c);
    c.skip_ws();
    if (c.next() != ':') throw parse_error("json: se esperaba ':'");
    c.skip_ws();

    value v;
    if (c.peek() == '"') {
      v.k = value::kind::string;
      v.str = parse_string(c);
    } else if (c.peek() == '-' || (c.peek() >= '0' && c.peek() <= '9')) {
      v.k = value::kind::integer;
      v.integer = parse_integer(c);
    } else {
      throw parse_error("json: valor inválido");
    }

    if (!obj.emplace(key, v).second) {
      throw parse_error("json: clave duplicada");
    }

    c.skip_ws();
    const char sep = c.next();
    if (sep == '}') break;
    if (sep != ',') throw parse_error("json: se esperaba ',' o '}'");
  }

  c.skip_ws();
  if (!c.at_end()) throw parse_error("json: datos sobrantes tras el objeto");
  return obj;
}

}  // namespace crypto::json
