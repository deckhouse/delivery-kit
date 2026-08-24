# Configuration Validation Contract

## Input

An image entry in `werf.yaml` may contain a `packages` sequence. Each entry has a `type`; an `os-pm` entry uses an inline list in `spec`.

## Rule

For each image configuration, the number of entries with `packages[].type: os-pm` MUST be zero or one. The rule is independent of list order and of the entries’ package names, `workdir`, `spec`, `lock`, and `env` values.

Package types other than `os-pm` are not restricted by this rule and may continue to appear multiple times.

## Failure behavior

When the count is two or greater, configuration validation MUST stop before package-install command generation or build execution and return a configuration error whose diagnostic:

- identifies the `packages` section;
- names `os-pm`; and
- states that only one `os-pm` directive is allowed (equivalent wording is acceptable if it clearly expresses the same limit).

The diagnostic should include the existing rendered source-document context.

## Compatibility

Configurations with zero or one `os-pm` directive MUST preserve existing per-entry validation and build behavior.
