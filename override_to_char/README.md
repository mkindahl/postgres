# override_to_char

Experimental module that intercepts `to_char(timestamptz, text)` (built-in OID 1770). The replacement prints a `NOTICE` and then calls the real `to_char`.

It works by overwriting the `func` pointer in the compiled-in `fmgr_builtins[]` dispatch table. This is **undefined behavior** (mutating a `const` object) and relies on `mprotect()` to make the read-only table writable. Use for experimentation only.

## Build & install

```bash
cd override_to_char
make PG_CONFIG=/path/to/your/postgres/bin/pg_config
make PG_CONFIG=/path/to/your/postgres/bin/pg_config install
```

## Try it in one session

```sql
LOAD 'override_to_char';
SELECT to_char(now(), 'YYYY-MM-DD');
-- NOTICE:  override_to_char: intercepted to_char(timestamptz), format="YYYY-MM-DD"
--  to_char
-- ------------
--  2026-08-24
```

Only the backend that ran `LOAD` is patched, and only calls that dispatch through fmgr are affected (i.e. not `DirectFunctionCall`).

## Patch every backend

Add to `postgresql.conf` and restart:

```
shared_preload_libraries = 'override_to_char'
```

Each backend patches its own copy of the table in `_PG_init`.

## Caveats

- Undefined behavior; not a supported PostgreSQL API.
- On hardened/code-signed builds (notably macOS `__DATA_CONST`), `mprotect` may fail — then this approach is not usable there.
- Only OID 1770 is patched; the other seven `to_char` overloads are untouched.
- Cached `FmgrInfo` structs initialized before the patch keep the original pointer.
