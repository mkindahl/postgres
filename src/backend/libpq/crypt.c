/*-------------------------------------------------------------------------
 *
 * crypt.c
 *	  Functions for dealing with encrypted passwords stored in
 *	  pg_auth_password (and pg_authid.rolpassword as a fallback).
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/backend/libpq/crypt.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <unistd.h>

#include "access/genam.h"
#include "access/htup_details.h"
#include "access/table.h"
#include "utils/rel.h"
#include "catalog/pg_auth_password.h"
#include "catalog/pg_authid.h"
#include "common/md5.h"
#include "common/scram-common.h"
#include "libpq/crypt.h"
#include "libpq/scram.h"
#include "miscadmin.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/memutils.h"
#include "utils/syscache.h"
#include "utils/timestamp.h"

/* Threshold for password expiration warnings. */
int			password_expiration_warning_threshold = 604800;

/* Maximum allowed rotation window duration in minutes (0 = no limit). */
int			password_rotation_max_duration = 1440;

/* Enables deprecation warnings for MD5 passwords. */
bool		md5_password_warnings = true;

/*
 * qsort comparator: sort RolePasswordEntry by position descending so that
 * PREVIOUS 1 (passposition = -1, most recently retired) appears first.
 */
static int
compare_password_position(const void *a, const void *b)
{
	const RolePasswordEntry *ea = (const RolePasswordEntry *) a;
	const RolePasswordEntry *eb = (const RolePasswordEntry *) b;

	if (ea->position > eb->position)
		return -1;
	if (ea->position < eb->position)
		return 1;
	return 0;
}

/*
 * Fetch stored passwords for a user, for authentication.
 *
 * Returns a RolePasswordInfo with the CURRENT password and any active
 * PREVIOUS passwords whose rotation window has not expired.  On error,
 * returns NULL and stores a palloc'd explanation in *logdetail (for the
 * server log only — never send to the client).
 *
 * Reads from pg_auth_password first; falls back to pg_authid.rolpassword
 * so that roles created before this catalog existed still authenticate.
 */
RolePasswordInfo *
get_role_password(const char *role, const char **logdetail)
{
	HeapTuple	roleTup;
	Oid			roleoid;
	Relation	rel;
	ScanKeyData skey;
	SysScanDesc scan;
	HeapTuple	tuple;
	RolePasswordInfo *info;
	int			prev_alloc = 8;
	int			nprev = 0;
	TimestampTz now;
	Datum		datum;
	bool		isnull;

	/* Verify the role exists and get its OID */
	roleTup = SearchSysCache1(AUTHNAME, PointerGetDatum(role));
	if (!HeapTupleIsValid(roleTup))
	{
		*logdetail = psprintf(_("Role \"%s\" does not exist."), role);
		return NULL;
	}
	roleoid = ((Form_pg_authid) GETSTRUCT(roleTup))->oid;
	ReleaseSysCache(roleTup);

	now = GetCurrentTimestamp();
	info = palloc0(sizeof(RolePasswordInfo));
	info->previous = palloc(sizeof(RolePasswordEntry) * prev_alloc);

	/* Scan pg_auth_password for all entries belonging to this role */
	rel = table_open(AuthPasswordRelationId, AccessShareLock);

	ScanKeyInit(&skey,
				Anum_pg_auth_password_passroleid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(roleoid));

	scan = systable_beginscan(rel, AuthPasswordRoleidPositionIndexId,
							  true, NULL, 1, &skey);

	while ((tuple = systable_getnext(scan)) != NULL)
	{
		Form_pg_auth_password pwform = (Form_pg_auth_password) GETSTRUCT(tuple);
		RolePasswordEntry entry;

		memset(&entry, 0, sizeof(entry));
		entry.position = (int) pwform->passposition;

		datum = heap_getattr(tuple, Anum_pg_auth_password_passtext,
							 RelationGetDescr(rel), &isnull);
		if (isnull)
			continue;			/* shouldn't happen (BKI_FORCE_NOT_NULL) */
		entry.passtext = TextDatumGetCString(datum);

		datum = heap_getattr(tuple, Anum_pg_auth_password_passvaliduntil,
							 RelationGetDescr(rel), &isnull);
		entry.validuntil_isnull = isnull;
		if (!isnull)
			entry.validuntil = DatumGetTimestampTz(datum);

		datum = heap_getattr(tuple, Anum_pg_auth_password_passchanged,
							 RelationGetDescr(rel), &isnull);
		entry.changed_isnull = isnull;
		if (!isnull)
			entry.changed = DatumGetTimestampTz(datum);

		if (entry.position == 0)
		{
			info->current = entry;
		}
		else if (entry.position < 0 &&
				 (entry.validuntil_isnull || entry.validuntil >= now))
		{
			/* Include only previous passwords still within their rotation window */
			if (nprev >= prev_alloc)
			{
				prev_alloc *= 2;
				info->previous = repalloc(info->previous,
										  sizeof(RolePasswordEntry) * prev_alloc);
			}
			info->previous[nprev++] = entry;
		}
	}

	systable_endscan(scan);
	table_close(rel, AccessShareLock);

	info->nprevious = nprev;

	/*
	 * If there is no CURRENT entry in pg_auth_password (e.g. the role
	 * predates this catalog), fall back to pg_authid.rolpassword.
	 */
	if (info->current.passtext == NULL)
	{
		roleTup = SearchSysCache1(AUTHNAME, PointerGetDatum(role));
		Assert(HeapTupleIsValid(roleTup));

		datum = SysCacheGetAttr(AUTHNAME, roleTup,
								Anum_pg_authid_rolpassword, &isnull);
		if (!isnull)
		{
			info->current.position = 0;
			info->current.passtext = TextDatumGetCString(datum);

			datum = SysCacheGetAttr(AUTHNAME, roleTup,
									Anum_pg_authid_rolvaliduntil, &isnull);
			info->current.validuntil_isnull = isnull;
			if (!isnull)
				info->current.validuntil = DatumGetTimestampTz(datum);
		}
		ReleaseSysCache(roleTup);
	}

	if (info->current.passtext == NULL)
	{
		*logdetail = psprintf(_("User \"%s\" has no password assigned."), role);
		pfree(info->previous);
		pfree(info);
		return NULL;
	}

	/* Sort previous entries most-recently-retired first */
	if (nprev > 1)
		qsort(info->previous, nprev, sizeof(RolePasswordEntry),
			  compare_password_position);

	/*
	 * Check whether the current password has expired.  Previous passwords
	 * have their own validuntil (rotation-window end), already filtered above.
	 */
	if (!info->current.validuntil_isnull)
	{
		uint64		expire_time;

		if (info->current.validuntil < now)
		{
			*logdetail = psprintf(_("User \"%s\" has an expired password."), role);
			pfree(info->previous);
			pfree(info);
			return NULL;
		}

		expire_time = TimestampDifferenceMicroseconds(now, info->current.validuntil);

		if (expire_time / USECS_PER_SEC < (uint64) password_expiration_warning_threshold)
		{
			MemoryContext oldcontext;
			int			days;
			int			hours;
			int			minutes;
			char	   *warning;
			char	   *detail;

			oldcontext = MemoryContextSwitchTo(TopMemoryContext);

			days = expire_time / USECS_PER_DAY;
			hours = (expire_time % USECS_PER_DAY) / USECS_PER_HOUR;
			minutes = (expire_time % USECS_PER_HOUR) / USECS_PER_MINUTE;

			warning = pstrdup(_("role password will expire soon"));

			if (days > 0)
				detail = psprintf(ngettext("The password for role \"%s\" will expire in %d day.",
										   "The password for role \"%s\" will expire in %d days.",
										   days),
								  role, days);
			else if (hours > 0)
				detail = psprintf(ngettext("The password for role \"%s\" will expire in %d hour.",
										   "The password for role \"%s\" will expire in %d hours.",
										   hours),
								  role, hours);
			else if (minutes > 0)
				detail = psprintf(ngettext("The password for role \"%s\" will expire in %d minute.",
										   "The password for role \"%s\" will expire in %d minutes.",
										   minutes),
								  role, minutes);
			else
				detail = psprintf(_("The password for role \"%s\" will expire in less than 1 minute."),
								  role);

			StoreConnectionWarning(warning, detail, NULL);

			MemoryContextSwitchTo(oldcontext);
		}
	}

	return info;
}

/*
 * What kind of a password type is 'shadow_pass'?
 */
PasswordType
get_password_type(const char *shadow_pass)
{
	char	   *encoded_salt;
	int			iterations;
	int			key_length = 0;
	pg_cryptohash_type hash_type;
	uint8		stored_key[SCRAM_MAX_KEY_LEN];
	uint8		server_key[SCRAM_MAX_KEY_LEN];

	if (strncmp(shadow_pass, "md5", 3) == 0 &&
		strlen(shadow_pass) == MD5_PASSWD_LEN &&
		strspn(shadow_pass + 3, MD5_PASSWD_CHARSET) == MD5_PASSWD_LEN - 3)
		return PASSWORD_TYPE_MD5;
	if (parse_scram_secret(shadow_pass, &iterations, &hash_type, &key_length,
						   &encoded_salt, stored_key, server_key))
		return PASSWORD_TYPE_SCRAM_SHA_256;
	return PASSWORD_TYPE_PLAINTEXT;
}

/*
 * Given a user-supplied password, convert it into a secret of
 * 'target_type' kind.
 *
 * If the password is already in encrypted form, we cannot reverse the
 * hash, so it is stored as it is regardless of the requested type.
 */
char *
encrypt_password(PasswordType target_type, const char *role,
				 const char *password)
{
	PasswordType guessed_type = get_password_type(password);
	char	   *encrypted_password = NULL;
	const char *errstr = NULL;

	if (guessed_type != PASSWORD_TYPE_PLAINTEXT)
	{
		/*
		 * Cannot convert an already-encrypted password from one format to
		 * another, so return it as it is.
		 */
		encrypted_password = pstrdup(password);
	}
	else
	{
		switch (target_type)
		{
			case PASSWORD_TYPE_MD5:
				encrypted_password = palloc(MD5_PASSWD_LEN + 1);

				if (!pg_md5_encrypt(password, (const uint8 *) role, strlen(role),
									encrypted_password, &errstr))
					elog(ERROR, "password encryption failed: %s", errstr);
				break;

			case PASSWORD_TYPE_SCRAM_SHA_256:
				encrypted_password = pg_be_scram_build_secret(password);
				break;

			case PASSWORD_TYPE_PLAINTEXT:
				elog(ERROR, "cannot encrypt password with 'plaintext'");
				break;
		}
	}

	Assert(encrypted_password);

	/*
	 * Valid password hashes may be very long, but we don't want to store
	 * anything that might need out-of-line storage, since de-TOASTing won't
	 * work during authentication because we haven't selected a database yet
	 * and cannot read pg_class. 512 bytes should be more than enough for all
	 * practical use, so fail for anything longer.
	 */
	if (encrypted_password &&	/* keep compiler quiet */
		strlen(encrypted_password) > MAX_ENCRYPTED_PASSWORD_LEN)
	{
		/*
		 * We don't expect any of our own hashing routines to produce hashes
		 * that are too long.
		 */
		Assert(guessed_type != PASSWORD_TYPE_PLAINTEXT);

		ereport(ERROR,
				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
				 errmsg("encrypted password is too long"),
				 errdetail("Encrypted passwords must be no longer than %d bytes.",
						   MAX_ENCRYPTED_PASSWORD_LEN)));
	}

	if (md5_password_warnings &&
		get_password_type(encrypted_password) == PASSWORD_TYPE_MD5)
		ereport(WARNING,
				(errcode(ERRCODE_WARNING_DEPRECATED_FEATURE),
				 errmsg("setting an MD5-encrypted password"),
				 errdetail("MD5 password support is deprecated and will be removed in a future release of PostgreSQL."),
				 errhint("Refer to the PostgreSQL documentation for details about migrating to another password type.")));

	return encrypted_password;
}

/*
 * Check MD5 authentication response, and return STATUS_OK or STATUS_ERROR.
 *
 * 'shadow_pass' is the user's correct password or password hash, as stored
 * in pg_authid.rolpassword.
 * 'client_pass' is the response given by the remote user to the MD5 challenge.
 * 'md5_salt' is the salt used in the MD5 authentication challenge.
 *
 * In the error case, save a string at *logdetail that will be sent to the
 * postmaster log (but not the client).
 */
int
md5_crypt_verify(const char *role, const char *shadow_pass,
				 const char *client_pass,
				 const uint8 *md5_salt, int md5_salt_len,
				 const char **logdetail)
{
	int			retval;
	char		crypt_pwd[MD5_PASSWD_LEN + 1];
	const char *errstr = NULL;

	Assert(md5_salt_len > 0);

	if (get_password_type(shadow_pass) != PASSWORD_TYPE_MD5)
	{
		/* incompatible password hash format. */
		*logdetail = psprintf(_("User \"%s\" has a password that cannot be used with MD5 authentication."),
							  role);
		return STATUS_ERROR;
	}

	/*
	 * Compute the correct answer for the MD5 challenge.
	 */
	/* stored password already encrypted, only do salt */
	if (!pg_md5_encrypt(shadow_pass + strlen("md5"),
						md5_salt, md5_salt_len,
						crypt_pwd, &errstr))
	{
		*logdetail = errstr;
		return STATUS_ERROR;
	}

	if (strlen(client_pass) == strlen(crypt_pwd) &&
		timingsafe_bcmp(client_pass, crypt_pwd, strlen(crypt_pwd)) == 0)
		retval = STATUS_OK;
	else
	{
		*logdetail = psprintf(_("Password does not match for user \"%s\"."),
							  role);
		retval = STATUS_ERROR;
	}

	return retval;
}

/*
 * Check given password for given user, and return STATUS_OK or STATUS_ERROR.
 *
 * 'shadow_pass' is the user's correct password hash, as stored in
 * pg_authid.rolpassword.
 * 'client_pass' is the password given by the remote user.
 *
 * In the error case, store a string at *logdetail that will be sent to the
 * postmaster log (but not the client).
 */
int
plain_crypt_verify(const char *role, const char *shadow_pass,
				   const char *client_pass,
				   const char **logdetail)
{
	char		crypt_client_pass[MD5_PASSWD_LEN + 1];
	const char *errstr = NULL;

	/*
	 * Client sent password in plaintext.  If we have an MD5 hash stored, hash
	 * the password the client sent, and compare the hashes.  Otherwise
	 * compare the plaintext passwords directly.
	 */
	switch (get_password_type(shadow_pass))
	{
		case PASSWORD_TYPE_SCRAM_SHA_256:
			if (scram_verify_plain_password(role,
											client_pass,
											shadow_pass))
			{
				return STATUS_OK;
			}
			else
			{
				*logdetail = psprintf(_("Password does not match for user \"%s\"."),
									  role);
				return STATUS_ERROR;
			}
			break;

		case PASSWORD_TYPE_MD5:
			if (!pg_md5_encrypt(client_pass,
								(const uint8 *) role,
								strlen(role),
								crypt_client_pass,
								&errstr))
			{
				*logdetail = errstr;
				return STATUS_ERROR;
			}
			if (strlen(crypt_client_pass) == strlen(shadow_pass) &&
				timingsafe_bcmp(crypt_client_pass, shadow_pass, strlen(shadow_pass)) == 0)
				return STATUS_OK;
			else
			{
				*logdetail = psprintf(_("Password does not match for user \"%s\"."),
									  role);
				return STATUS_ERROR;
			}
			break;

		case PASSWORD_TYPE_PLAINTEXT:

			/*
			 * We never store passwords in plaintext, so this shouldn't
			 * happen.
			 */
			break;
	}

	/*
	 * This shouldn't happen.  Plain "password" authentication is possible
	 * with any kind of stored password hash.
	 */
	*logdetail = psprintf(_("Password of user \"%s\" is in unrecognized format."),
						  role);
	return STATUS_ERROR;
}

/*
 * Check given password against all active entries in a RolePasswordInfo,
 * trying CURRENT first, then PREVIOUS entries in rotation-window order.
 *
 * Returns STATUS_OK if any entry matches, STATUS_ERROR otherwise.
 */
int
plain_crypt_verify_with_rotation(const char *role, RolePasswordInfo *info,
								 const char *client_pass,
								 const char **logdetail)
{
	int			i;

	/* Try the current password first */
	if (plain_crypt_verify(role, info->current.passtext,
						   client_pass, logdetail) == STATUS_OK)
		return STATUS_OK;

	/* Try each previous password (rotation window) in recency order */
	for (i = 0; i < info->nprevious; i++)
	{
		if (plain_crypt_verify(role, info->previous[i].passtext,
							   client_pass, logdetail) == STATUS_OK)
			return STATUS_OK;
	}

	*logdetail = psprintf(_("Password does not match for user \"%s\"."), role);
	return STATUS_ERROR;
}
