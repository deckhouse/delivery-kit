---
title: "werf.yaml template engine"
type: reference
sources: [S012]
updated: 2026-07-30
---

The `werf.yaml` template engine is based on Go's `text/template` with Sprig (70+ functions) and custom werf functions. (S012)

## Commit information

- `.Commit.Hash` — current commit SHA. Avoid using it when possible as it may trigger many unneeded stage rebuilds. (S012)
- `.Commit.Date.Human` — commit date in human-readable form. (S012)
- `.Commit.Date.Unix` — commit date in Unix epoch seconds. (S012)

## Template inclusion

- `include "<TEMPLATE_NAME>" <VALUES>` — renders another template and passes the result through. (S012)
- `tpl "<STRING>" <VALUES>` — evaluates a string as a template. The string can be a project file content, an environment variable value, or an arbitrary string. (S012)

## File access

- `.Files.Exists "<FILE_PATH>"` — returns `true`/`false` whether a file or directory exists in the project. (S012)
- `.Files.Get "<FILE_PATH>"` — returns the content of a project file. (S012)
- `.Files.Glob "<GLOB>"` — returns a dict of files matching the glob pattern. Supports shell pattern matching and `**`. Results can be merged with Sprig's `merge` function. (S012)
- `.Files.IsDir "<PATH>"` — returns `true`/`false` whether the path is a directory. (S012)

By default, use of files with non-committed changes is not allowed by giterminism. (S012)

## Utility functions

- `required "<ERROR_MSG>" <VALUE>` — fails template rendering if the value is empty. (S012)
- `fromYaml "<STRING>"` — decodes a YAML document into a structure. (S012)
- `toYaml <STRUCTURE>` — encodes a structure into a YAML document. (S012)

## Template directory

Template files with the `.tmpl` extension can be stored in the `.werf` directory (arbitrary nesting `.werf/**/*.tmpl` is supported). They share a common context with the `werf.yaml` configuration file:

- A template file can be included by relative path: `{{ include "directory/partial.tmpl" . }}`. (S012)
- Templates defined with `define` in one template file are available in any other, including `werf.yaml`. (S012)

---

See also: [werf.yaml environment variables](./werf-yaml-env.md) for `.Env` and `env` function details.