# Changelog

## Add support for AES-GCM key wrap algorithms(https://github.com/jwt/ruby-jwe/pull/38) (2025-10-08)

**Features:**
- Add support for AES-GCM key wrap algorithms (A128GCMKW, A192GCMKW, A256GCMKW)
- Add new internal architecture with `Base`, `Validator`, `Header`, and `NameResolver` classes
- Improve code organization with refactored module structure
- RuboCop compliance improvements

**Deprecations:**

- Deprecated `JWE.check_params`, `JWE.check_alg`, `JWE.check_enc`, `JWE.check_zip`, `JWE.check_key`
(use `JWE::Validator` instead)
- Deprecated `JWE.param_to_class_name` (use `JWE::NameResolver` instead)
- Deprecated internal methods `JWE.apply_zip`, `JWE.generate_header`, `JWE.generate_serialization`

**Notes:**

All deprecated methods remain functional with deprecation warnings for backward compatibility.

## [v1.1.1](https://github.com/jwt/ruby-jwe/tree/v1.1.1) (2025-08-07)

[Full Changelog](https://github.com/jwt/ruby-jwe/compare/v1.1.0...v1.1.1)

**Fixes and enhancements:**

- Fix tag length checking for AES-GCM (CVE-2025-54887)

## [v1.1.0](https://github.com/jwt/ruby-jwe/tree/v1.1.0) (2025-07-22)

[Full Changelog](https://github.com/jwt/ruby-jwe/compare/v1.0.0...v1.1.0)

**Features:**

- Add RsaOaep256 algorithm (https://github.com/jwt/ruby-jwe/pull/31)

## [v1.0.0](https://github.com/jwt/ruby-jwe/tree/v1.0.0) (2025-02-16)

[Full Changelog](https://github.com/jwt/ruby-jwe/compare/v0.4.0...v1.0.0)

**Features:**

- Support Ruby 3.4 (https://github.com/jwt/ruby-jwe/pull/26)
- Drop support for Ruby versions prior to 2.5 (https://github.com/jwt/ruby-jwe/pull/27)

**Fixes and enhancements:**

- Refreshed codebase (CI and linter fixes) (https://github.com/jwt/ruby-jwe/pull/27, https://github.com/jwt/ruby-jwe/pull/28)
