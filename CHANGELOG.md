# Changelog

## [v1.1.2](https://github.com/jwt/ruby-jwe/tree/v1.1.2) (2026-11-26)

[Full Changelog](https://github.com/jwt/ruby-jwe/compare/v1.1.1...v1.1.2)

**Fixes and enhancements:**

- Use implicit rejection for RSA1_5 CEK decryption to prevent a PKCS#1 v1.5 padding oracle (GHSA-9hgp-rr8g-x7cq)
- Limit DEF decompressed content to 1 MiB to prevent decompression bombs (GHSA-qwvx-w3vv-2r28)

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
