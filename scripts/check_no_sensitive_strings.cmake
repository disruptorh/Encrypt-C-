# Script: check_no_sensitive_strings.cmake
# Verifies that the shipped binary does not contain residual test secrets
# (passwords, pepper values, plaintexts) as string literals.
#
# Invoked by CTest as:
#   cmake -DBIN=... -DSCRIPT_DIR=... -P check_no_sensitive_strings.cmake
#
# The test suite (separate binary) obviously contains these values; the
# application binary must NOT, even after a test run. `strings` output is
# scanned for each known test value (case-insensitive substring).

if(NOT EXISTS "${BIN}")
  message(FATAL_ERROR "binary not found: ${BIN}")
endif()

execute_process(
  COMMAND strings "${BIN}"
  OUTPUT_VARIABLE STRINGS_OUTPUT
  RESULT_VARIABLE STRINGS_RESULT
)
if(NOT STRINGS_RESULT EQUAL 0)
  message(FATAL_ERROR "strings failed")
endif()

# Values used by the unit tests / KATs. Keep in sync with tests/.
set(FORBIDDEN
  "Correct Horse Battery Staple"
  "p4ssw0rd"
  "mi-campo-secreto"
  "contrase\u00f1a-de-prueba-1"
  "Texto secreto que viaja en el sobre."
  "segundo texto con campo secreto"
  "datos a proteger"
  "par\u00e1metros autenticados"
  "Ladies and Gentlemen of the class of '99"
)

foreach(v IN LISTS FORBIDDEN)
  string(TOLOWER "${STRINGS_OUTPUT}" lower_output)
  string(TOLOWER "${v}" lower_v)
  string(FIND "${lower_output}" "${lower_v}" pos)
  if(NOT pos EQUAL -1)
    message(FATAL_ERROR "FAIL: binary contains test secret string: '${v}'")
  endif()
endforeach()

message(STATUS "OK: no residual test secrets in ${BIN}")
