#include "crypto/base64.hpp"

#include <array>

namespace crypto {

namespace {

constexpr char kAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// Reverse lookup table: -1 for invalid characters.
constexpr std::array<std::int8_t, 256> build_lookup() {
  std::array<std::int8_t, 256> table{};
  for (std::size_t i = 0; i < 256; ++i) table[i] = -1;
  for (std::size_t i = 0; i < 64; ++i) {
    table[static_cast<std::uint8_t>(kAlphabet[i])] = static_cast<std::int8_t>(i);
  }
  return table;
}

constexpr std::array<std::int8_t, 256> kLookup = build_lookup();

}  // namespace

void base64url_encode_to(const std::uint8_t* data, std::size_t len,
                         std::string& out) {
  const std::size_t chunks = len / 3;
  const std::size_t rem = len % 3;
  std::size_t i = 0;
  for (std::size_t c = 0; c < chunks; ++c) {
    const std::uint32_t v = (static_cast<std::uint32_t>(data[i]) << 16) |
                            (static_cast<std::uint32_t>(data[i + 1]) << 8) |
                            static_cast<std::uint32_t>(data[i + 2]);
    out.push_back(kAlphabet[(v >> 18) & 0x3f]);
    out.push_back(kAlphabet[(v >> 12) & 0x3f]);
    out.push_back(kAlphabet[(v >> 6) & 0x3f]);
    out.push_back(kAlphabet[v & 0x3f]);
    i += 3;
  }
  if (rem == 1) {
    const std::uint32_t v = static_cast<std::uint32_t>(data[i]);
    out.push_back(kAlphabet[(v >> 2) & 0x3f]);
    out.push_back(kAlphabet[(v << 4) & 0x3f]);
  } else if (rem == 2) {
    const std::uint32_t v = (static_cast<std::uint32_t>(data[i]) << 8) |
                            static_cast<std::uint32_t>(data[i + 1]);
    out.push_back(kAlphabet[(v >> 10) & 0x3f]);
    out.push_back(kAlphabet[(v >> 4) & 0x3f]);
    out.push_back(kAlphabet[(v << 2) & 0x3f]);
  }
}

std::string base64url_encode(const std::uint8_t* data, std::size_t len) {
  std::string out;
  out.reserve((len + 2) / 3 * 4);
  base64url_encode_to(data, len, out);
  return out;
}

std::string base64url_decode(const std::string& in) {
  if (in.empty()) throw base64_error("base64 vacío");
  if (in.size() % 4 == 1) throw base64_error("base64 con longitud inválida");

  std::string out;
  out.reserve(in.size() * 3 / 4);

  std::size_t i = 0;
  const std::size_t full_chunks = in.size() / 4;
  const std::size_t rem = in.size() % 4;

  for (std::size_t c = 0; c < full_chunks; ++c) {
    const std::int32_t a = kLookup[static_cast<std::uint8_t>(in[i])];
    const std::int32_t b = kLookup[static_cast<std::uint8_t>(in[i + 1])];
    const std::int32_t d = kLookup[static_cast<std::uint8_t>(in[i + 2])];
    const std::int32_t e = kLookup[static_cast<std::uint8_t>(in[i + 3])];
    if (a < 0 || b < 0 || d < 0 || e < 0) {
      throw base64_error("carácter base64 inválido");
    }
    const std::uint32_t v = (static_cast<std::uint32_t>(a) << 18) |
                            (static_cast<std::uint32_t>(b) << 12) |
                            (static_cast<std::uint32_t>(d) << 6) |
                            static_cast<std::uint32_t>(e);
    out.push_back(static_cast<char>((v >> 16) & 0xff));
    out.push_back(static_cast<char>((v >> 8) & 0xff));
    out.push_back(static_cast<char>(v & 0xff));
    i += 4;
  }

  if (rem == 2) {
    const std::int32_t a = kLookup[static_cast<std::uint8_t>(in[i])];
    const std::int32_t b = kLookup[static_cast<std::uint8_t>(in[i + 1])];
    if (a < 0 || b < 0) throw base64_error("carácter base64 inválido");
    if ((b & 0x0f) != 0) throw base64_error("base64 con bits de relleno no canónicos");
    out.push_back(static_cast<char>((a << 2) | (b >> 4)));
  } else if (rem == 3) {
    const std::int32_t a = kLookup[static_cast<std::uint8_t>(in[i])];
    const std::int32_t b = kLookup[static_cast<std::uint8_t>(in[i + 1])];
    const std::int32_t d = kLookup[static_cast<std::uint8_t>(in[i + 2])];
    if (a < 0 || b < 0 || d < 0) throw base64_error("carácter base64 inválido");
    if ((d & 0x03) != 0) throw base64_error("base64 con bits de relleno no canónicos");
    const std::uint32_t v = (static_cast<std::uint32_t>(a) << 10) |
                            (static_cast<std::uint32_t>(b) << 4) |
                            static_cast<std::uint32_t>(d >> 2);
    out.push_back(static_cast<char>((v >> 8) & 0xff));
    out.push_back(static_cast<char>(v & 0xff));
  }

  return out;
}

}  // namespace crypto
