# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.1] - 2025-08-04

### Changed

- Drop `tslib` dependency

## [2.0.0] - 2025-02-06

### Changed

- Drop support for Node < 18 and update `nock` dependency to next major version `v14`

## [1.1.0] - 2024-07-05

### Added

- New method on JWT `withoutKeyId` allows to easily remove an existing `kid` header
- New issuer method `signString` allows to sign arbitrary strings. This allows
  to validate against completly invalid JWTs, e.g. a payload that does not
  represent a correct JSON object

## [1.0.0] - 2024-06-24

### Added

- When signing a JWT, a specific kid can be specified. This allows to create
  tokens which are signed with an incorrect key

## [0.10.0] - 2024-06-17

### Fixed

- Fix generation of JWT signature.

### Added

- new method on JWT `unknownKid()` to generate a random value for the `kid`
  header. This normally causes the `kid` to not match any previously generated
  key
- new method on JWT `withIssuer` to quickly update the `iss` claim on the current
  JWT

## [0.9.3] - 2024-06-13

### Fixed

- Ensure imports are compliant with `verbatimModuleSyntax`

## [0.9.2] - 2024-06-09

### Fixed

- Automate publishing workflow

## [0.9.1] - 2024-06-09

### Changed

- Fixed release workflow

## [0.9.0] - 2024-06-09

### Added

- Initial code
