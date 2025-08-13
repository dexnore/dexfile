# Changelog

All notable changes to **Dexfile** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),  
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Initial changelog creation.
- Support for extended Dockerfile syntax with all standard Dockerfile instructions.
- `IMPORT` instruction with options for `--platform`, `--target`, `--file`, `--opt`.
- `CTR`/`ENDCTR` block for ephemeral container execution.
- `PROC` instruction for process execution inside containers; supports `--timeout`.
- `EXEC` instruction, running commands in ephemeral containers with BuildKit protobuf state output; supports `--timeout`.
- `.dexnore` ignorefile support.
- Conditional instructions: `IF`, `ELSE IF`, `ELSE`, `ENDIF` (all supporting `--timeout`).
- Looping: `FOR`/`ENDFOR` with `--delim` and `--timeout`.
- Reusable functions: `FUNC`/`ENDFUNC`/`FUNC CALL` with argument passing and defaults.
- Documentation: `README.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `SECURITY.md`, `MAINTAINERS`, `NOTICE`, `CHANGELOG.md`.

### Changed
- _No changes yet_

### Deprecated
- _Nothing deprecated_

### Removed
- _Nothing removed_

### Fixed
- _No fixes yet_

---
