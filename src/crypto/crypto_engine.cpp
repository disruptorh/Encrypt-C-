#include "crypto/crypto_engine.hpp"

#include <cstdint>
#include <cstring>
#include <limits>
#include <unistd.h>

#include "crypto/aead.hpp"

namespace crypto {

namespace {

constexpr std::uint64_t kBaselineMemoryBytes = 48ULL * 1024 * 1024;
constexpr std::uint64_t kTextOverheadFactor = 10ULL;
constexpr std::uint64_t kBudgetFractionNum = 9;  // 0.9
constexpr std::uint64_t kBudgetFractionDen = 10;

constexpr const char* kAuthErrorMessage =
    "Fallo de autenticación: contraseña o campo secreto incorrectos, o datos "
    "manipulados.";

std::uint64_t system_ram_bytes() {
  const long pages = sysconf(_SC_PHYS_PAGES);
  const long page_size = sysconf(_SC_PAGE_SIZE);
  if (pages <= 0 || page_size <= 0) return 0;
  if (static_cast<std::uint64_t>(pages) >
      (std::numeric_limits<std::uint64_t>::max() /
       static_cast<std::uint64_t>(page_size))) {
    return 0;
  }
  return static_cast<std::uint64_t>(pages) *
         static_cast<std::uint64_t>(page_size);
}

}  // namespace

bool check_size_budget(std::size_t kdf_mem_kib, std::size_t plaintext_bytes) {
  const std::uint64_t max_ram = system_ram_bytes();
  if (max_ram == 0) return true;  // cannot measure: fail open, as in Kotlin

  // Guard against overflow.
  if (static_cast<std::uint64_t>(plaintext_bytes) >
      (std::numeric_limits<std::uint64_t>::max() - kBaselineMemoryBytes) /
          kTextOverheadFactor) {
    return false;
  }
  const std::uint64_t estimated =
      kBaselineMemoryBytes +
      static_cast<std::uint64_t>(kdf_mem_kib) * 1024ULL +
      static_cast<std::uint64_t>(plaintext_bytes) * kTextOverheadFactor;
  // estimated < max_ram * 0.9, overflow-safe
  if (max_ram >=
      (std::numeric_limits<std::uint64_t>::max() / kBudgetFractionDen)) {
    return true;  // RAM too big to multiply: trivially fits
  }
  const std::uint64_t budget = max_ram * kBudgetFractionNum / kBudgetFractionDen;
  return estimated < budget;
}

std::string encrypt(const secure_mem::byte_buffer& plaintext,
                    const secure_mem::secure_string& password,
                    const secure_mem::secure_string* pepper,
                    const kdf_profile& profile) {
  if (password.empty()) {
    throw crypto_exception("La contraseña es obligatoria");
  }
  if (!check_size_budget(profile.mem_kib, plaintext.size())) {
    throw crypto_exception(
        "Memoria insuficiente para procesar este contenido. Reduce el tamaño "
        "o usa el perfil Estándar.");
  }

  secure_mem::byte_buffer salt;
  salt.resize(envelope::kSaltBytes);
  randombytes_buf(salt.data(), salt.size());

  const secure_mem::secure_string* pepper_ptr =
      (pepper != nullptr && !pepper->empty()) ? pepper : nullptr;

  // key is a secure_mem::byte_buffer: wiped by its destructor on scope exit,
  // including on exception.
  secure_mem::byte_buffer key =
      derive_key(password, salt, pepper_ptr, profile);

  const std::string aad =
      envelope::build_aad(envelope::kVersion, envelope::kAeadName,
                          envelope::kKdfName, profile.ops, profile.mem_kib);

  aead_result sealed = aead_encrypt(
      key, plaintext, reinterpret_cast<const std::uint8_t*>(aad.data()),
      aad.size());

  envelope e;
  e.version = envelope::kVersion;
  e.aead_name = envelope::kAeadName;
  e.kdf_name = envelope::kKdfName;
  e.ops = profile.ops;
  e.mem_kib = profile.mem_kib;
  e.salt = std::move(salt);
  e.nonce = std::move(sealed.nonce);
  e.ciphertext = std::move(sealed.ciphertext);

  return envelope_to_base64(e);
}

secure_mem::byte_buffer decrypt(
    const std::string& blob, const secure_mem::secure_string& password,
    const secure_mem::secure_string* pepper) {
  if (blob.empty()) throw crypto_exception("No hay sobre que descifrar");
  if (password.empty()) throw crypto_exception("La contraseña es obligatoria");

  envelope e;
  try {
    e = envelope_from_base64(blob);
  } catch (const envelope_exception& ex) {
    throw crypto_exception(ex.what());
  }

  // The blob is Base64 (~4/3 of the JSON), so estimate the plaintext size to
  // apply the same budget as encryption.
  const std::size_t estimated_plaintext =
      blob.size() > (std::numeric_limits<std::size_t>::max() * 3ULL / 4ULL)
          ? std::numeric_limits<std::size_t>::max()
          : blob.size() * 3 / 4;
  if (!check_size_budget(e.mem_kib, estimated_plaintext)) {
    throw crypto_exception(
        "Este sobre requiere demasiada memoria para este dispositivo. "
        "Memoria insuficiente para descifrarlo.");
  }

  const secure_mem::secure_string* pepper_ptr =
      (pepper != nullptr && !pepper->empty()) ? pepper : nullptr;

  // RAII: the derived key is wiped on every path, including authentication
  // failures and exceptions.
  secure_mem::byte_buffer key =
      derive_key(password, e.salt, pepper_ptr, kdf_profile{e.ops, e.mem_kib, {}});

  const std::string aad =
      envelope::build_aad(e.version, e.aead_name, e.kdf_name, e.ops, e.mem_kib);

  try {
    return aead_decrypt(key, e.nonce, e.ciphertext,
                        reinterpret_cast<const std::uint8_t*>(aad.data()),
                        aad.size());
  } catch (const authentication_error&) {
    throw crypto_exception(kAuthErrorMessage);
  }
}

}  // namespace crypto
