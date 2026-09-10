/*-------------------------------------------------------------------------
 *
 * pg_auth_password.h
 *	  definition of the "role passwords" system catalog (pg_auth_password)
 *
 * pg_auth_password stores one row per active password entry for a role.
 * passposition = 0 is the CURRENT (active) password; negative values are
 * PREVIOUS entries kept alive during a rotation window.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/catalog/pg_auth_password.h
 *
 * NOTES
 *	  The Catalog.pm module reads this file and derives schema
 *	  information.
 *
 *-------------------------------------------------------------------------
 */
#ifndef PG_AUTH_PASSWORD_H
#define PG_AUTH_PASSWORD_H

#include "catalog/genbki.h"
#include "catalog/pg_auth_password_d.h"

/* ----------------
 *		pg_auth_password definition.  cpp turns this into
 *		typedef struct FormData_pg_auth_password
 * ----------------
 */
CATALOG(pg_auth_password,4551,AuthPasswordRelationId) BKI_SHARED_RELATION BKI_ROWTYPE_OID(4552,AuthPasswordRelation_Rowtype_Id) BKI_SCHEMA_MACRO
{
	Oid			oid;			/* row identifier */
	Oid			passroleid BKI_LOOKUP(pg_authid);	/* OID of the owning role */

	/*
	 * passposition = 0:   CURRENT password (active, must be valid)
	 * passposition = -1:  PREVIOUS 1 (most recent retired password)
	 * passposition = -2:  PREVIOUS 2, etc.
	 * Positive values are never stored.
	 */
	int32		passposition;

#ifdef CATALOG_VARLEN			/* variable-length fields start here */
	text		passtext BKI_FORCE_NOT_NULL;	/* SCRAM-SHA-256 or MD5 hash */
	timestamptz passvaliduntil BKI_FORCE_NULL;	/* hard expiry (CURRENT) or
												 * window close (PREVIOUS) */
	timestamptz passchanged BKI_FORCE_NULL;		/* when this entry was created */
#endif
} FormData_pg_auth_password;

/* ----------------
 *		Form_pg_auth_password corresponds to a pointer to a tuple with
 *		the format of pg_auth_password relation.
 * ----------------
 */
typedef FormData_pg_auth_password *Form_pg_auth_password;

DECLARE_TOAST_WITH_MACRO(pg_auth_password, 9122, 9133, PgAuthPasswordToastTable, PgAuthPasswordToastIndex);

/* One row per (role, position) pair */
DECLARE_UNIQUE_INDEX(pg_auth_password_roleid_position_index, 9134, AuthPasswordRoleidPositionIndexId, pg_auth_password, btree(passroleid oid_ops, passposition int4_ops));

/* Used to look up all passwords for a given role via SearchSysCacheList1 */
MAKE_SYSCACHE(AUTHPASSWORD, pg_auth_password_roleid_position_index, 8);

#endif							/* PG_AUTH_PASSWORD_H */
