
# Copyright (c) 2021-2026, PostgreSQL Global Development Group

# Tests for live authentication behavior during password rotation.
#
# Covers:
#   - SCRAM-SHA-256: both CURRENT and PREVIOUS 1 accepted while window is open
#   - SCRAM-SHA-256: old password rejected after window is closed
#   - SCRAM-SHA-256: rotation window expiry via past VALID UNTIL
#   - SCRAM-SHA-256: multiple rotations; only active PREVIOUS entries accepted
#   - Plaintext password auth: same dual-accept behavior
#   - MD5 auth: only CURRENT password accepted (no rotation window)
#
# Catalog-level DDL behavior is tested separately in
# src/test/regress/sql/password_rotation.sql.
#
# This test can only run with Unix-domain sockets.

use strict;
use warnings FATAL => 'all';
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

if (!$use_unix_sockets)
{
	plan skip_all =>
	  "authentication tests cannot run without Unix-domain sockets";
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Rewrite pg_hba.conf with a single local entry for (database, role, method)
# and reload the server.
sub reset_pg_hba
{
	my ($node, $database, $role, $method) = @_;
	unlink($node->data_dir . '/pg_hba.conf');
	$node->append_conf('pg_hba.conf', "local $database $role $method");
	$node->reload;
	return;
}

# Attempt a connection and report pass/fail with a descriptive name.
sub test_conn
{
	local $Test::Builder::Level = $Test::Builder::Level + 1;
	my ($node, $connstr, $description, $want_ok) = @_;
	if ($want_ok)
	{
		$node->connect_ok($connstr, $description);
	}
	else
	{
		$node->connect_fails($connstr, $description);
	}
}

# ---------------------------------------------------------------------------
# Cluster setup
# ---------------------------------------------------------------------------

my $node = PostgreSQL::Test::Cluster->new('primary');
$node->init;
$node->append_conf('postgresql.conf', "password_encryption = 'scram-sha-256'");
$node->start;

# ---------------------------------------------------------------------------
# SCRAM-SHA-256 rotation tests
# ---------------------------------------------------------------------------

# Create the test role with an initial SCRAM password.
$node->safe_psql(
	'postgres',
	"SET password_encryption = 'scram-sha-256';
     CREATE ROLE rot_scram LOGIN PASSWORD 'v1';"
);

reset_pg_hba($node, 'all', 'rot_scram', 'scram-sha-256');
$ENV{PGPASSWORD} = 'v1';
test_conn($node, 'user=rot_scram', 'SCRAM: initial password authenticates',
	1);

# --- Rotate to v2 with an open-ended window (VALID UNTIL = infinity) ------

$node->safe_psql('postgres',
	"ALTER ROLE rot_scram NEXT PASSWORD 'v2' VALID UNTIL 'infinity';");

# New password works immediately.
$ENV{PGPASSWORD} = 'v2';
test_conn($node, 'user=rot_scram',
	'SCRAM: new password accepted right after rotation', 1);

# Old password still works (within the rotation window).
$ENV{PGPASSWORD} = 'v1';
test_conn($node, 'user=rot_scram',
	'SCRAM: previous password accepted during open rotation window', 1);

# A completely wrong password is still rejected.
$ENV{PGPASSWORD} = 'wrong';
test_conn($node, 'user=rot_scram',
	'SCRAM: wrong password rejected during rotation window', 0);

# --- Close the window with DROP PREVIOUS PASSWORD -------------------------

$node->safe_psql('postgres', 'ALTER ROLE rot_scram DROP PREVIOUS PASSWORD;');

$ENV{PGPASSWORD} = 'v2';
test_conn($node, 'user=rot_scram',
	'SCRAM: current password still works after explicit window close', 1);

$ENV{PGPASSWORD} = 'v1';
test_conn($node, 'user=rot_scram',
	'SCRAM: previous password rejected after window explicitly closed', 0);

# --- Rotation window expiry via a past VALID UNTIL timestamp --------------
#
# Strategy: rotate to v3 with VALID UNTIL in the past.  That sets the
# newly-demoted previous entry's passvaliduntil to the past date, making the
# window already expired.  A second rotation to v4 (no VALID UNTIL) promotes
# the expired previous v3 to PREVIOUS 2 while installing v4 as CURRENT with
# passvaliduntil = NULL.  get_role_password() skips PREVIOUS entries whose
# passvaliduntil < now(), so v3's expired entry is never offered to SCRAM.

# First get back to a clean state: a single current password v2.
$node->safe_psql('postgres',
	"ALTER ROLE rot_scram DROP ALL PASSWORDS;
     ALTER ROLE rot_scram PASSWORD 'v2';"
);

$node->safe_psql('postgres',
	"ALTER ROLE rot_scram NEXT PASSWORD 'v3' VALID UNTIL '2000-01-01';");

# v3 has passvaliduntil='2000-01-01' as CURRENT, so the role's own
# password expiry is also in the past.  We rotate again immediately to
# install a valid CURRENT (v4) and push v3 into an already-expired previous.
$node->safe_psql('postgres',
	"ALTER ROLE rot_scram NEXT PASSWORD 'v4';");

# v4 is current (no expiry) → succeeds.
$ENV{PGPASSWORD} = 'v4';
test_conn($node, 'user=rot_scram',
	'SCRAM: current password works when previous window is expired', 1);

# v3 was demoted to PREVIOUS 1 with passvaliduntil=NULL (window_end=NULL when
# installing v4), so it IS accepted during the v4 window.
$ENV{PGPASSWORD} = 'v3';
test_conn($node, 'user=rot_scram',
	'SCRAM: previous 1 (no deadline) accepted', 1);

# v2 was shifted to PREVIOUS 2 and retains passvaliduntil='2000-01-01',
# which is in the past → excluded from auth candidates → rejected.
$ENV{PGPASSWORD} = 'v2';
test_conn($node, 'user=rot_scram',
	'SCRAM: previous 2 with expired window is rejected', 0);

# --- Multiple rotations: only PREVIOUS 1 and 2 are in-window -------------
#
# After four rotations from a clean start the chain is:
#   pos  0: v5  (passvaliduntil = infinity)
#   pos -1: v4  (passvaliduntil = NULL, window open)
#   pos -2: v3  (passvaliduntil = NULL, window open)
#   pos -3: v2  (passvaliduntil = NULL, window open)
#   pos -4: v1_b (passvaliduntil = NULL, window open)
#
# All previous entries have no deadline so all five passwords should
# be accepted.  We then prune to PREVIOUS 2 and verify that only v5, v4,
# v3 remain accepted while v2 and v1_b are not.

$node->safe_psql(
	'postgres',
	"ALTER ROLE rot_scram DROP ALL PASSWORDS;
     ALTER ROLE rot_scram PASSWORD 'v1_b';"
);
$node->safe_psql('postgres',
	"ALTER ROLE rot_scram NEXT PASSWORD 'v2_b' VALID UNTIL 'infinity';");
$node->safe_psql('postgres',
	"ALTER ROLE rot_scram NEXT PASSWORD 'v3_b' VALID UNTIL 'infinity';");
$node->safe_psql('postgres',
	"ALTER ROLE rot_scram NEXT PASSWORD 'v4_b' VALID UNTIL 'infinity';");
$node->safe_psql('postgres',
	"ALTER ROLE rot_scram NEXT PASSWORD 'v5_b' VALID UNTIL 'infinity';");

for my $pass (qw(v5_b v4_b v3_b v2_b v1_b))
{
	$ENV{PGPASSWORD} = $pass;
	test_conn($node, 'user=rot_scram',
		"SCRAM: $pass accepted (all five entries in window)", 1);
}

# Prune to keep only 2 previous entries.
$node->safe_psql('postgres',
	'ALTER ROLE rot_scram DROP PASSWORDS OLDER THAN PREVIOUS 2;');

# v5_b (current), v4_b, v3_b still accepted.
for my $pass (qw(v5_b v4_b v3_b))
{
	$ENV{PGPASSWORD} = $pass;
	test_conn($node, 'user=rot_scram',
		"SCRAM: $pass still accepted after pruning to PREVIOUS 2", 1);
}

# v2_b and v1_b were pruned and are now rejected.
for my $pass (qw(v2_b v1_b))
{
	$ENV{PGPASSWORD} = $pass;
	test_conn($node, 'user=rot_scram',
		"SCRAM: $pass rejected after pruning removed its entry", 0);
}

# --- DROP ALL PASSWORDS: role becomes inaccessible via password auth ------

$node->safe_psql('postgres', 'ALTER ROLE rot_scram DROP ALL PASSWORDS;');

for my $pass (qw(v5_b v4_b v3_b))
{
	$ENV{PGPASSWORD} = $pass;
	test_conn($node, 'user=rot_scram',
		"SCRAM: $pass rejected after DROP ALL PASSWORDS", 0);
}

# ---------------------------------------------------------------------------
# Plaintext password (method=password) rotation tests
# ---------------------------------------------------------------------------
#
# The cleartext challenge path uses plain_crypt_verify_with_rotation(), which
# also checks all active previous entries in order.

$node->safe_psql(
	'postgres',
	"SET password_encryption = 'scram-sha-256';
     CREATE ROLE rot_plain LOGIN PASSWORD 'p1';"
);

reset_pg_hba($node, 'all', 'rot_plain', 'password');

$ENV{PGPASSWORD} = 'p1';
test_conn($node, 'user=rot_plain', 'plaintext: initial password works', 1);

$node->safe_psql('postgres',
	"ALTER ROLE rot_plain NEXT PASSWORD 'p2' VALID UNTIL 'infinity';");

$ENV{PGPASSWORD} = 'p2';
test_conn($node, 'user=rot_plain',
	'plaintext: new password works after rotation', 1);

$ENV{PGPASSWORD} = 'p1';
test_conn($node, 'user=rot_plain',
	'plaintext: old password accepted during window', 1);

$node->safe_psql('postgres', 'ALTER ROLE rot_plain DROP PREVIOUS PASSWORD;');

$ENV{PGPASSWORD} = 'p2';
test_conn($node, 'user=rot_plain',
	'plaintext: current password works after closing window', 1);

$ENV{PGPASSWORD} = 'p1';
test_conn($node, 'user=rot_plain',
	'plaintext: old password rejected after window closed', 0);

# ---------------------------------------------------------------------------
# MD5 rotation tests
# ---------------------------------------------------------------------------
#
# MD5 authentication always uses only the CURRENT password.  Previous
# entries are never offered.

my $md5_works = ($node->psql('postgres', "SELECT md5('')") == 0);

SKIP:
{
	skip "MD5 not supported in this build", 4 unless $md5_works;

	$node->safe_psql(
		'postgres',
		"SET password_encryption = 'md5';
         CREATE ROLE rot_md5 LOGIN PASSWORD 'm1';"
	);

	reset_pg_hba($node, 'all', 'rot_md5', 'md5');

	$ENV{PGPASSWORD} = 'm1';
	test_conn($node, 'user=rot_md5', 'MD5: initial password works', 1);

	# Rotate while still in MD5 mode so both entries are MD5 hashes.
	$node->safe_psql(
		'postgres',
		"SET password_encryption = 'md5';
         ALTER ROLE rot_md5 NEXT PASSWORD 'm2' VALID UNTIL 'infinity';"
	);

	$ENV{PGPASSWORD} = 'm2';
	test_conn($node, 'user=rot_md5',
		'MD5: new (current) password accepted', 1);

	# MD5 auth only checks the CURRENT password; m1 must be rejected even
	# though the window is open.
	$ENV{PGPASSWORD} = 'm1';
	test_conn($node, 'user=rot_md5',
		'MD5: previous password rejected (MD5 auth is current-only)', 0);

	$node->safe_psql('postgres', 'DROP ROLE rot_md5;');
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

reset_pg_hba($node, 'all', 'all', 'trust');
$node->safe_psql('postgres', 'DROP ROLE rot_scram;');
$node->safe_psql('postgres', 'DROP ROLE rot_plain;');

done_testing();
