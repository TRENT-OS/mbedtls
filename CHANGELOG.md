# Changelog

All notable changes by HENSOLDT Cyber GmbH to this 3rd party module included in
the TRENTOS-M SDK will be documented in this file.

For more details it is recommended to compare the module at hand with the
previous release or the baseline of the 3rd party module.

## [1.2]

### Fixed

- Fix a misplaced `#endif` in `library/ssl_tls.c` to remove unnecessary debug
output.

## [1.1]

### Changed

- Expose `dhm_check_range()` as part of a public interface.
- Align with changes in the TRENTOS-M Crypto API by renaming key attribute from
`exportable` to `keepLocal`.

### Added

- Update mbedTLS by merging version v2.16.8, tag mbedtls-2.16.8.

## [1.0]

### Changed

- Use the generic dataport default size `OS_DATAPORT_DEFAULT_SIZE`.
- Adapt the `OS_CryptoMac_init()` function call to receive a MAC key object to
conform to the changes in the TRENTOS-M Crypto API.
- Add the responsibility of allocating the digest object to the
`OS_CryptoDigest_clone()` function instead of always calling
`OS_CryptoDigest_init()` first.
- Adapt the overall error handling by:
  - replacing the `SEOS_` prefix in error code names with `OS_`,
  - renaming the error type from `seos_err_t` to `OS_Error_t`,
  - replacing the usage of `Debug_hexDump()` with the `Debug_DUMP()` macro,
  - adding the error translation code to the mbedTLS build.
- Set keyData structure to zero before exporting it in
`trentos_ssl_cli_export_cert_key()`.
- Expose `x509_name_cmp()` as a public function.
- Replace TRENTOS-M specific implementation in `crypto.h/.c` with separate files
based on functionality and replace mbedTLS log functions with TRENTOS-M log
functions in newly created files:
  - `trentos_ssl_cli.h/.c`,
  - `trentos_ssl_tls.h/.c`,
  - `trentos_x509_crt.h/.c`,
- Adjust function prototypes to pass only `hCrypto` handle instead of the SSL
context where possible.
- Adjust the build system to have 3 separate build targets for:
  - crypto,
  - certification,
  - TLS.
- Add `platform.c` to the build so it is possible to overwrite `calloc()` and
`free()` with customized implementations.

### Fixed

- Properly free the MAC/Key objects in case of an error.
- Change error messages to correctly output the failing function from
`OS_CryptoMac_init()` to `OS_CryptoMac_process()`/`OS_CryptoMac_finalize()`.

### Added

- Add TRENTOS-M specific configuration file `configs/config-trentos-m.h`.

## [0.9]

### Changed

- Apply code formatting changes.

### Added

- Adding an option to mbedTLS to use TRENTOS-M Crypto API for:
  - server signatures,
  - RSA certificate verification,
  - ECDH-based key exchanges,
  - DHM-based key exchange,
  - RF and session checksum,
  - AES-GCM encryption.
- Adding TRENTOS-M specific implementation by adding files `library/crypto.c`
and `include/mbedtls/crypto.h`.
- Start integration of mbedTLS based on commit ec904e which is based on version
2.16.0 from <https://github.com/ARMmbed/mbedtls>.
