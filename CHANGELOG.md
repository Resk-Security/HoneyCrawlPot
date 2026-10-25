# Changelog

## [0.2.1] - 2026-10-25

### Fixed
- Native Node ESM import failed with `ERR_MODULE_NOT_FOUND` because the
  compiled output kept extensionless relative imports. The build now emits
  explicit `.js` specifiers.
- CI runs a Node import smoke test in addition to the Bun suite.
