# override_to_char

Experimental module that intercepts `to_char(timestamptz, text)` (built-in OID 1770). The replacement checks for the CVE-2026-14669 heap-overflow condition — an over-long session time zone abbreviation used with a `TZ`/`tz` format item — and raises an error instead of calling the vulnerable built-in when that would overflow; otherwise it calls the real `to_char`.

It works by overwriting the `func` pointer in the compiled-in `fmgr_builtins[]` dispatch table. This is **undefined behavior** (mutating a `const` object) and relies on `mprotect()` to make the read-only table writable. Use for experimentation only.

> **Linux only.** This does not work on macOS.

## Build & install

```bash
cd override_to_char
make PG_CONFIG=/path/to/your/postgres/bin/pg_config
make PG_CONFIG=/path/to/your/postgres/bin/pg_config install
```

## Try it in one session

```sql
LOAD 'override_to_char';

-- Normal calls are unaffected:
SELECT to_char(now(), 'YYYY-MM-DD HH24:MI TZ');
--        to_char
-- ----------------------
--  2026-08-24 07:24 UTC

-- An over-long POSIX time zone abbreviation used with a TZ item is rejected,
-- instead of overflowing to_char's output buffer:
SET timezone = '<AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA>0';
SELECT to_char(now(), 'TZ');
-- ERROR:  time zone format value too long
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
- Only OID 1770 is patched; the other seven `to_char` overloads are untouched.
- Cached `FmgrInfo` structs initialized before the patch keep the original pointer.
