--
-- Tests for password rotation DDL (pg_auth_password catalog)
--

-- These tests verify the catalog-level behavior of the rotation DDL.
-- Live authentication flows are covered in src/test/authentication/.
--
-- SCRAM-SHA-256 secrets contain a random salt, so all passtext values are
-- masked with regexp_replace to produce stable expected output.

-- Shorthand macro used throughout: mask one SCRAM-SHA-256 passtext value.
-- Separate queries repeat it to keep each test self-contained.

-- -----------------------------------------------------------------------
-- Setup
-- -----------------------------------------------------------------------

SET password_encryption = 'scram-sha-256';

CREATE ROLE regress_rottest LOGIN PASSWORD 'first';
CREATE ROLE regress_rottest_expired LOGIN PASSWORD 'v1';
CREATE ROLE regress_rottest_older LOGIN PASSWORD 'v1';
CREATE ROLE regress_rottest_all LOGIN PASSWORD 'v1';

-- -----------------------------------------------------------------------
-- Initial state: PASSWORD writes a CURRENT entry to pg_auth_password
-- -----------------------------------------------------------------------

-- After CREATE/ALTER with PASSWORD, there should be exactly one CURRENT entry.
SELECT passposition,
       regexp_replace(passtext,
           '(SCRAM-SHA-256)\$(\d+):([a-zA-Z0-9+/=]+)\$([a-zA-Z0-9+/=]+):([a-zA-Z0-9+/=]+)',
           '\1$\2:<salt>$<storedkey>:<serverkey>') AS passtext_masked,
       passvaliduntil IS NULL AS no_deadline
FROM pg_auth_password
WHERE passroleid = 'regress_rottest'::regrole
ORDER BY passposition DESC;

-- pg_authid.rolpassword must equal the CURRENT passtext (write-through).
SELECT (a.rolpassword = p.passtext) AS rolpassword_matches_current
FROM pg_authid a
JOIN pg_auth_password p ON p.passroleid = a.oid AND p.passposition = 0
WHERE a.rolname = 'regress_rottest';

-- -----------------------------------------------------------------------
-- NEXT PASSWORD: first rotation
-- -----------------------------------------------------------------------

ALTER ROLE regress_rottest NEXT PASSWORD 'second';

-- Two entries: CURRENT (0) and PREVIOUS 1 (-1).
SELECT passposition,
       regexp_replace(passtext,
           '(SCRAM-SHA-256)\$(\d+):([a-zA-Z0-9+/=]+)\$([a-zA-Z0-9+/=]+):([a-zA-Z0-9+/=]+)',
           '\1$\2:<salt>$<storedkey>:<serverkey>') AS passtext_masked,
       passvaliduntil IS NULL AS no_deadline
FROM pg_auth_password
WHERE passroleid = 'regress_rottest'::regrole
ORDER BY passposition DESC;

-- pg_authid write-through still tracks the new CURRENT.
SELECT (a.rolpassword = p.passtext) AS rolpassword_matches_current
FROM pg_authid a
JOIN pg_auth_password p ON p.passroleid = a.oid AND p.passposition = 0
WHERE a.rolname = 'regress_rottest';

-- -----------------------------------------------------------------------
-- NEXT PASSWORD: second rotation (three entries total)
-- -----------------------------------------------------------------------

ALTER ROLE regress_rottest NEXT PASSWORD 'third';

SELECT passposition,
       regexp_replace(passtext,
           '(SCRAM-SHA-256)\$(\d+):([a-zA-Z0-9+/=]+)\$([a-zA-Z0-9+/=]+):([a-zA-Z0-9+/=]+)',
           '\1$\2:<salt>$<storedkey>:<serverkey>') AS passtext_masked,
       passvaliduntil IS NULL AS no_deadline
FROM pg_auth_password
WHERE passroleid = 'regress_rottest'::regrole
ORDER BY passposition DESC;

-- -----------------------------------------------------------------------
-- NEXT PASSWORD with VALID UNTIL: deadline recorded on demoted entry
-- -----------------------------------------------------------------------

-- Rotate with a rotation-window deadline far in the future.
ALTER ROLE regress_rottest NEXT PASSWORD 'fourth' VALID UNTIL 'infinity';

-- The newly-demoted PREVIOUS 1 (was 'third', now at -1 after shift)
-- and the new CURRENT both get passvaliduntil = 'infinity'.
SELECT passposition,
       regexp_replace(passtext,
           '(SCRAM-SHA-256)\$(\d+):([a-zA-Z0-9+/=]+)\$([a-zA-Z0-9+/=]+):([a-zA-Z0-9+/=]+)',
           '\1$\2:<salt>$<storedkey>:<serverkey>') AS passtext_masked,
       passvaliduntil
FROM pg_auth_password
WHERE passroleid = 'regress_rottest'::regrole
ORDER BY passposition DESC;

-- -----------------------------------------------------------------------
-- DROP PREVIOUS PASSWORD: removes only PREVIOUS 1
-- -----------------------------------------------------------------------

-- Reset to a clean two-entry state first.
DROP ROLE regress_rottest;
CREATE ROLE regress_rottest LOGIN PASSWORD 'v1';
ALTER ROLE regress_rottest NEXT PASSWORD 'v2';
ALTER ROLE regress_rottest NEXT PASSWORD 'v3';

-- Three entries before drop.
SELECT passposition
FROM pg_auth_password
WHERE passroleid = 'regress_rottest'::regrole
ORDER BY passposition DESC;

ALTER ROLE regress_rottest DROP PREVIOUS PASSWORD;

-- PREVIOUS 1 (-1) removed; CURRENT (0) and PREVIOUS 2 (-2) remain.
SELECT passposition
FROM pg_auth_password
WHERE passroleid = 'regress_rottest'::regrole
ORDER BY passposition DESC;

-- Calling DROP PREVIOUS PASSWORD when there is no PREVIOUS 1 is a no-op.
ALTER ROLE regress_rottest DROP PREVIOUS PASSWORD;

SELECT passposition
FROM pg_auth_password
WHERE passroleid = 'regress_rottest'::regrole
ORDER BY passposition DESC;

-- -----------------------------------------------------------------------
-- DROP EXPIRED PASSWORDS
-- -----------------------------------------------------------------------

-- Build a state where one PREVIOUS entry has an already-expired deadline.
--
-- Step 1: rotate with VALID UNTIL in the past → newly-demoted v1 gets
--         passvaliduntil = '2000-01-01' (expired immediately).
ALTER ROLE regress_rottest_expired NEXT PASSWORD 'v2' VALID UNTIL '2000-01-01';

-- Step 2: rotate again without VALID UNTIL → v2 is demoted to PREVIOUS 1
--         with passvaliduntil = NULL; v1 shifts to PREVIOUS 2 retaining
--         the expired deadline.
ALTER ROLE regress_rottest_expired NEXT PASSWORD 'v3';

-- Three entries: CURRENT (null deadline), PREVIOUS 1 (null), PREVIOUS 2 (expired).
SELECT passposition,
       passvaliduntil IS NULL AS no_deadline,
       (passvaliduntil IS NOT NULL AND passvaliduntil < now()) AS is_expired
FROM pg_auth_password
WHERE passroleid = 'regress_rottest_expired'::regrole
ORDER BY passposition DESC;

ALTER ROLE regress_rottest_expired DROP EXPIRED PASSWORDS;

-- Only the expired PREVIOUS 2 was removed.
SELECT passposition,
       passvaliduntil IS NULL AS no_deadline
FROM pg_auth_password
WHERE passroleid = 'regress_rottest_expired'::regrole
ORDER BY passposition DESC;

-- DROP EXPIRED PASSWORDS never removes CURRENT, even if its deadline is past.
ALTER ROLE regress_rottest_expired NEXT PASSWORD 'v4' VALID UNTIL '2000-01-01';
ALTER ROLE regress_rottest_expired DROP EXPIRED PASSWORDS;

SELECT passposition
FROM pg_auth_password
WHERE passroleid = 'regress_rottest_expired'::regrole
ORDER BY passposition DESC;

-- -----------------------------------------------------------------------
-- DROP PASSWORDS OLDER THAN PREVIOUS N
-- -----------------------------------------------------------------------

-- Build: five entries (CURRENT + PREVIOUS 1..4).
ALTER ROLE regress_rottest_older NEXT PASSWORD 'v2';
ALTER ROLE regress_rottest_older NEXT PASSWORD 'v3';
ALTER ROLE regress_rottest_older NEXT PASSWORD 'v4';
ALTER ROLE regress_rottest_older NEXT PASSWORD 'v5';

SELECT passposition
FROM pg_auth_password
WHERE passroleid = 'regress_rottest_older'::regrole
ORDER BY passposition DESC;

-- Keep only the 2 most recent previous entries; delete PREVIOUS 3 and 4.
ALTER ROLE regress_rottest_older DROP PASSWORDS OLDER THAN PREVIOUS 2;

SELECT passposition
FROM pg_auth_password
WHERE passroleid = 'regress_rottest_older'::regrole
ORDER BY passposition DESC;

-- N=0 drops all PREVIOUS entries (keeps only CURRENT).
ALTER ROLE regress_rottest_older DROP PASSWORDS OLDER THAN PREVIOUS 0;

SELECT passposition
FROM pg_auth_password
WHERE passroleid = 'regress_rottest_older'::regrole
ORDER BY passposition DESC;

-- N larger than the number of previous entries is a no-op.
ALTER ROLE regress_rottest_older NEXT PASSWORD 'v6';
ALTER ROLE regress_rottest_older DROP PASSWORDS OLDER THAN PREVIOUS 99;

SELECT passposition
FROM pg_auth_password
WHERE passroleid = 'regress_rottest_older'::regrole
ORDER BY passposition DESC;

-- -----------------------------------------------------------------------
-- DROP ALL PASSWORDS
-- -----------------------------------------------------------------------

ALTER ROLE regress_rottest_all NEXT PASSWORD 'v2';
ALTER ROLE regress_rottest_all NEXT PASSWORD 'v3';

-- Three entries before.
SELECT COUNT(*) AS entry_count
FROM pg_auth_password
WHERE passroleid = 'regress_rottest_all'::regrole;

ALTER ROLE regress_rottest_all DROP ALL PASSWORDS;

-- Catalog is empty for this role.
SELECT COUNT(*) AS entry_count
FROM pg_auth_password
WHERE passroleid = 'regress_rottest_all'::regrole;

-- pg_authid.rolpassword is cleared to NULL.
SELECT rolpassword IS NULL AS rolpassword_cleared
FROM pg_authid
WHERE rolname = 'regress_rottest_all';

-- DROP ALL PASSWORDS on a role with no entries is a no-op.
ALTER ROLE regress_rottest_all DROP ALL PASSWORDS;

SELECT COUNT(*) AS entry_count
FROM pg_auth_password
WHERE passroleid = 'regress_rottest_all'::regrole;

-- -----------------------------------------------------------------------
-- GUC: password_rotation_max_duration
-- -----------------------------------------------------------------------

SHOW password_rotation_max_duration;

SET password_rotation_max_duration = 60;  -- 60 minutes = 1 hour
SHOW password_rotation_max_duration;

SET password_rotation_max_duration = 0;  -- 0 means no limit
SHOW password_rotation_max_duration;

-- Restore default.
RESET password_rotation_max_duration;
SHOW password_rotation_max_duration;

-- -----------------------------------------------------------------------
-- Error cases
-- -----------------------------------------------------------------------

-- Empty password is rejected.
ALTER ROLE regress_rottest NEXT PASSWORD '';  -- error

-- PREVIOUS PASSWORD = CURRENT is parsed but not yet implemented.
ALTER ROLE regress_rottest PREVIOUS PASSWORD = CURRENT;  -- error

-- Duplicate option in the same command.
ALTER ROLE regress_rottest NEXT PASSWORD 'x' NEXT PASSWORD 'y';  -- error

-- -----------------------------------------------------------------------
-- Cleanup
-- -----------------------------------------------------------------------

DROP ROLE regress_rottest;
DROP ROLE regress_rottest_expired;
DROP ROLE regress_rottest_older;
DROP ROLE regress_rottest_all;

-- All entries must be gone after the roles are dropped.
SELECT COUNT(*) AS orphaned_entries
FROM pg_auth_password
WHERE passroleid NOT IN (SELECT oid FROM pg_authid);
