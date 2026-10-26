Fixtures were generated with CPython 3.14.4 from `module.py`, without importing it. They exercise actual timestamp, checked-hash and unchecked-hash `.pyc` bytes; the collector attributes paths from RECORD and does not validate Python bytecode or compare its source hash with RECORD's SHA-256.

The three `.pyc` fixtures are tracked despite the repository's `*.pyc` ignore rule. Regenerating them updates tracked files normally; add any new `.pyc` fixture explicitly with `git add -f`.

Regenerate from this directory with the same Python version:

```sh
python3 - <<'PY'
import os
import py_compile

os.utime('module.py', (1700000000, 1700000000))
for name, mode in (
    ('timestamp', py_compile.PycInvalidationMode.TIMESTAMP),
    ('checked', py_compile.PycInvalidationMode.CHECKED_HASH),
    ('unchecked', py_compile.PycInvalidationMode.UNCHECKED_HASH),
):
    py_compile.compile('module.py', cfile=name + '.pyc', dfile='module.py',
                       doraise=True, invalidation_mode=mode)
PY
```
