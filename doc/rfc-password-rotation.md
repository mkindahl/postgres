# RFC: Password Rotation for PostgreSQL

**Status:** Draft  
**Author:** Mats Kindahl <mats.kindahl@supabase.io>  
**Date:** 2026-09-10  
**Related work:** Gurjeet Singh's `multiple_passwords_v4` branch, CF 44/4432  

---

## Problem Statement

Fleet-wide credential rotation requires that both the old and new password are accepted simultaneously for a configurable window.  Without this capability, rotating credentials across many application servers is an all-or-nothing operation: changing the password in the database before all servers are updated causes authentication failures, and updating servers before the database change is impossible.

PostgreSQL currently offers no way to keep two passwords active at the same time.

---

## Goals

- Two passwords simultaneously active during a rotation window (no auth interruptions).
- SCRAM-SHA-256 works for both passwords using a shared-salt re-derivation trick.
- Rotation window duration configurable per rotation event, with a server-enforced GUC maximum.
- All existing SQL syntax continues unchanged.
- MD5 authentication continues to use only the current password (MD5's per-challenge random salt makes dual-password verification impossible).

## Non-Goals

- More than one previous password is *retained* in the catalog but only the single most-recently-retired entry is actively accepted during authentication (the window for older entries can be independently managed).
- Dump/restore support for rotation history (transient operational state, not needed in logical replicas or restored clusters).
- Protocol-level negotiation of authentication method (not part of this proposal; see "Limitations" below).

---

## Design Overview

### New catalog: `pg_auth_password`

A new shared catalog `pg_auth_password` (OID 4551) stores one row per (role, password slot):

| Column | Type | Description |
|---|---|---|
| `oid` | `oid` | Row identifier |
| `passroleid` | `oid` | Foreign key → `pg_authid.oid` |
| `passposition` | `int4` | `0` = CURRENT, `-1` = PREVIOUS 1, `-2` = PREVIOUS 2, … |
| `passtext` | `text` | Encrypted password (SCRAM-SHA-256 or MD5 hash) |
| `passvaliduntil` | `timestamptz` | End of rotation window (NULL = no deadline) |
| `passchanged` | `timestamptz` | When this entry was created |

`pg_authid.rolpassword` is kept as a write-through alias of the CURRENT entry for backward compatibility with existing tools.

### SCRAM shared-salt invariant

SCRAM commits to a single salt in `server-first-message` before it knows which credential the client will prove.  For the server to verify either the current or the previous password, both secrets must share the same salt.

When `NEXT PASSWORD 'new'` is issued, if the current secret is SCRAM-SHA-256, the new secret is derived with the *existing* salt extracted from the current entry (`pg_be_scram_build_secret_with_salt`).  Both entries then share salt + iteration-count, so the server can check either one against the client's proof.

### New GUC

`password_rotation_max_duration` (integer, seconds, default `86400`) — operator-configurable upper bound on how long a rotation window may remain open.  Set to `0` for no limit.  Settable via `postgresql.conf` / `SIGHUP`.

---

## SQL Syntax

All new clauses are additions to `ALTER ROLE` / `ALTER USER` / `CREATE USER`.  Existing syntax is unchanged.

### Rotate to a new password

```sql
ALTER ROLE alice NEXT PASSWORD 'new_secret';

-- With a rotation-window deadline (uses the existing VALID UNTIL clause):
ALTER ROLE alice NEXT PASSWORD 'new_secret' VALID UNTIL '2026-10-01 00:00:00+00';
```

**Semantics:**

1. Encrypt `'new_secret'` using the same SCRAM salt as the current password (if SCRAM; otherwise encrypt normally).
2. Demote the current CURRENT entry to PREVIOUS 1.  If `VALID UNTIL` is supplied, store that timestamp as the rotation-window deadline on the newly-demoted entry.
3. Insert the new encrypted password as CURRENT.
4. Update `pg_authid.rolpassword` (write-through alias).

During the rotation window, both the new and the old credential are accepted for login.  Once `passvaliduntil` passes on a PREVIOUS entry, only CURRENT is accepted.

### Roll back a rotation *(not yet implemented)*

```sql
ALTER ROLE alice PREVIOUS PASSWORD = CURRENT;
```

Promotes the most-recently-retired PREVIOUS back to CURRENT and demotes the current CURRENT to PREVIOUS 1.  Useful if the new password was deployed incorrectly.

### Drop only the most-recently-retired previous password

```sql
ALTER ROLE alice DROP PREVIOUS PASSWORD;
```

Removes the PREVIOUS 1 entry (`passposition = -1`).  All other entries are unaffected.

### Drop all expired previous passwords

```sql
ALTER ROLE alice DROP EXPIRED PASSWORDS;
```

Removes every PREVIOUS entry whose `passvaliduntil` is in the past.  CURRENT is unaffected.

### Prune to the N most recent previous passwords

```sql
-- Keep only the last 2 previous passwords:
ALTER ROLE alice DROP PASSWORDS OLDER THAN PREVIOUS 2;
```

Deletes entries with `passposition < -N` (i.e., entries older than the N most recent).  CURRENT (`passposition = 0`) is unaffected.

### Drop all passwords

```sql
ALTER ROLE alice DROP ALL PASSWORDS;
```

Deletes every entry in `pg_auth_password` for this role, including CURRENT.  The role becomes password-less.  Also clears `pg_authid.rolpassword`.

---

## Workflow Examples

### Example 1 — Zero-downtime fleet rotation

```sql
-- 1. Generate the new password and install it with a 24-hour window.
--    Both old and new passwords accepted for the next 24 hours.
ALTER ROLE appuser NEXT PASSWORD 'P@ssw0rd-v2'
  VALID UNTIL now() + interval '24 hours';

-- 2. Roll out the new password to all application servers over the next few hours.
--    Old password still works during rollout.

-- 3. After all servers are updated and the window has closed, clean up:
ALTER ROLE appuser DROP EXPIRED PASSWORDS;
```

### Example 2 — Emergency rollback

```sql
-- Something went wrong; revert to the previous credential.
-- (PREVIOUS PASSWORD = CURRENT not yet implemented; planned for next revision)
```

### Example 3 — Audit: inspect active entries

```sql
SELECT
    r.rolname,
    p.passposition,
    p.passchanged,
    p.passvaliduntil
FROM pg_auth_password p
JOIN pg_authid r ON r.oid = p.passroleid
ORDER BY r.rolname, p.passposition DESC;
```

### Example 4 — Cap history depth

```sql
-- After several rotations, keep only the single most recent previous entry:
ALTER ROLE appuser DROP PASSWORDS OLDER THAN PREVIOUS 1;
```

---

## Authentication Path

### SCRAM-SHA-256

The SASL machinery is extended to accept an array of secrets rather than a single shadow password.  During `scram_init`, secrets that share the same salt and iteration count as the primary (CURRENT) secret are admitted as "previous candidates".  `verify_client_proof` tries the CURRENT pair first, then iterates over previous candidates; whichever pair matches records its `ServerKey` for the `server-final-message`.

Only secrets sharing the CURRENT entry's salt are eligible as previous candidates.  Secrets with a different salt (e.g., because the old password predates the rotation feature, or because the DBA set a new salt) are silently skipped and those previous entries are not accepted.

### Password (plaintext challenge)

`plain_crypt_verify_with_rotation` tries CURRENT first, then iterates PREVIOUS entries in recency order.  The first match wins.

### MD5

Only the CURRENT password is used.  MD5's per-challenge random salt means the server cannot pre-compute a second proof.

---

## Limitations and Known Issues

### Protocol negotiation

PostgreSQL's authentication protocol does not negotiate the authentication method after the server chooses one based on `pg_hba.conf`.  This means that if a role's CURRENT and PREVIOUS passwords use different authentication methods (e.g., one SCRAM, one MD5), the authentication exchange will use the method appropriate for the CURRENT entry and the PREVIOUS entry with the other method will not be reachable.

In practice, rotating from MD5 to SCRAM requires the operator to leave MD5 permitted in `pg_hba.conf` until the window closes, or to accept a brief outage.  Rotating between two SCRAM passwords (the common case) works seamlessly.

For background on why PostgreSQL has no protocol negotiation, see the pgsql-hackers thread ["Protocol level auth method negotiation"](https://www.postgresql.org/message-id/flat/CABkgnnVVzULnUFbPL6D+Nfu4BGZFiMmSijuZVD8OWDT9yFUzZg@mail.gmail.com).

### `ROLLBACK PASSWORD` not yet implemented

The `PREVIOUS PASSWORD = CURRENT` rollback clause parses correctly but raises `ERROR: not yet implemented`.

### Dump/restore

`pg_dumpall` and `pg_dump` do not capture `pg_auth_password` history.  After a restore, only the CURRENT password (written through to `pg_authid.rolpassword`) is present.  This is intentional: rotation history is operational state, not schema.

---

## Catalog Changes

- New catalog `pg_auth_password`, OID 4551 (rowtype OID 4552).
- `pg_authid.rolpassword` and `pg_authid.rolvaliduntil` are now deprecated write-through aliases; their values continue to reflect CURRENT.
- Catalog version bumped to `202607171`.

---

## Implementation Status

| Component | Status |
|---|---|
| `pg_auth_password` catalog + BKI/Makefile/meson | Done |
| `crypt.c` — `get_role_password()` returns `RolePasswordInfo *` | Done |
| `user.c` — rotation helpers + `AlterRole` dispatch | Done |
| `gram.y` — new syntax tokens and productions | Done |
| `guc_parameters.dat` — `password_rotation_max_duration` | Done |
| `auth-scram.c` — multi-secret SCRAM + `pg_be_scram_build_secret_with_salt` | Done |
| `auth-sasl.c` / `auth.c` — secrets array plumbing | Done |
| `PREVIOUS PASSWORD = CURRENT` rollback | **Not implemented** |
| `pg_dumpall` support | Deferred |
| `pg_shadow` / system view updates | Deferred |
| Regression tests | Not started |
| Documentation | Not started |

---

## Prior Art and Upstream Objections

### Prior proposals

The topic has been discussed twice on pgsql-hackers:

- **Joshua Brindle (2022)** — ["Multiple passwords, interval expirations"](https://www.postgresql.org/message-id/CAGB+Vh5SQQorNDEKP+0G=smxHRhbhs+VkmQWD5Vh98fmn8X4dg@mail.gmail.com). A relatively complex model supporting interval-based expiry chains for an arbitrary number of passwords. Returned with feedback; never revised to address it.
- **Gurjeet Singh (2023)** — CF 44/4432 (branch `multiple_passwords_v4`). A deliberate simplification: at most two passwords per role (current + old), stored as two new columns in `pg_authid` (`rololdpassword`, `rololdvaliduntil`). Proposed syntax: `ALTER ROLE u1 ADD PASSWORD 'p2' VALID UNTIL '...'`. Returned with feedback in January 2024; no activity since.

Both proposals have been idle since early 2024 with no active patch author or reviewer.

### Objection 1 — Violation of the zero-one-infinity rule

Singh's design allowed exactly two passwords per role.  Reviewers (Jeff Davis, Nathan Bossart, Jacob Champion, Stephen Frost) objected that "exactly two" is an unprincipled limit.  Good system design allows zero, one, or arbitrarily many of a thing — never a fixed small number.  If two is useful, why not three?  The limit felt arbitrary and would constrain operators who might need overlapping rotation windows (e.g., a slow canary rollout that spans multiple rotations).

**Our response:** We store N entries in a separate `pg_auth_password` catalog rather than two fixed columns in `pg_authid`.  Operators manage depth explicitly:

```sql
-- Keep the last 3 previous entries, drop everything older:
ALTER ROLE alice DROP PASSWORDS OLDER THAN PREVIOUS 3;

-- Or enforce a hard limit of 1 by always dropping after each rotation:
ALTER ROLE alice NEXT PASSWORD 'new';
ALTER ROLE alice DROP PASSWORDS OLDER THAN PREVIOUS 1;
```

The server-enforced `password_rotation_max_duration` GUC caps *time* rather than count, giving operators the correct knob without encoding a fixed number into the schema.

### Objection 2 — Mixed-protocol passwords cannot both be verified

If a role's CURRENT and PREVIOUS passwords use different authentication methods (e.g., CURRENT is SCRAM-SHA-256, PREVIOUS is MD5), only one of them can be checked in a given authentication exchange.

The root cause is structural:

1. The server commits to an authentication method by sending `AuthenticationSASL` or `AuthenticationMD5` to the client.  This choice is made before the client sends any credential material.
2. Once the method is chosen, the exchange is bound to it.  The client cannot send SCRAM proof for MD5 or vice versa.
3. For SCRAM specifically, the server sends `server-first-message` (which includes the salt) before the client proves anything.  If CURRENT and PREVIOUS have different salts, the server must pick one salt — whichever credential used the other salt cannot be verified.

This means mixed-method rotation (e.g., a fleet migrating from MD5 to SCRAM) cannot be done seamlessly with any purely server-side change.  Reviewers felt this was a significant gap, since MD5→SCRAM migration is a common motivation for wanting rotation in the first place.

**Our response:** We acknowledge this as an inherent protocol limitation and document it explicitly.  Our implementation handles the important common case — rotating between two SCRAM-SHA-256 passwords — seamlessly, by enforcing the shared-salt invariant at rotation time (`pg_be_scram_build_secret_with_salt`).  For the MD5→SCRAM transition, operators must either:

- Accept a brief authentication outage (change the password and update all servers atomically), or
- Retain `md5` in `pg_hba.conf` alongside `scram-sha-256` during the transition window, then remove it once all clients have rotated.

A protocol-level solution (method negotiation) was discussed in a separate thread and is considered out of scope for this proposal; see the Limitations section.

### Objection 3 — `pg_authid` should not grow wider

Singh's approach added two columns to `pg_authid`.  `pg_authid` is a critical shared catalog read on every authentication; reviewers prefer not to widen it without strong justification, both for performance and for the catalog upgrade burden.

**Our response:** We introduce a separate `pg_auth_password` catalog.  `pg_authid` is unchanged except for a deprecation comment on `rolpassword`/`rolvaliduntil`.  The new catalog is only read when the authentication path needs password data, and a fallback to `pg_authid.rolpassword` preserves backward compatibility for roles that have not yet been rotated through the new system.

### Why the proposals stalled

Beyond the specific objections, both patches lacked a committed reviewer willing to drive them through commitfest.  The topic has community sympathy — the use case is real and well understood — but has not found a champion with the time to iterate on the design and address feedback cycles.  This RFC attempts to document the objections and our responses explicitly so that a future submission can open the review discussion at a higher level.
