# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
