/*-------------------------------------------------------------------------
 *
 * pg_authid.h
 *	  definition of the "authorization identifier" system catalog (pg_authid)
 *
 *	  pg_shadow and pg_group are now views on pg_authid.
 *
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/catalog/pg_authid.h
 *
 * NOTES
 *	  The Catalog.pm module reads this file and derives schema
 *	  information.
 *
 *-------------------------------------------------------------------------
 */
#ifndef PG_AUTHID_H
#define PG_AUTHID_H

#include "catalog/genbki.h"
#include "catalog/pg_authid_d.h"	/* IWYU pragma: export */

/* ----------------
 *		pg_authid definition.  cpp turns this into
 *		typedef struct FormData_pg_authid
 * ----------------
 */
BEGIN_CATALOG_STRUCT

CATALOG(pg_authid,1260,AuthIdRelationId) BKI_SHARED_RELATION BKI_ROWTYPE_OID(2842,AuthIdRelation_Rowtype_Id) BKI_SCHEMA_MACRO
{
	Oid			oid;			/* oid */
	NameData	rolname;		/* name of role */
	bool		rolsuper;		/* read this field via superuser() only! */
	bool		rolinherit;		/* inherit privileges from other roles? */
	bool		rolcreaterole;	/* allowed to create more roles? */
	bool		rolcreatedb;	/* allowed to create databases? */
	bool		rolcanlogin;	/* allowed to log in as session user? */
	bool		rolreplication; /* role used for streaming replication */
	bool		rolbypassrls;	/* bypasses row-level security? */
	int32		rolconnlimit;	/* max connections allowed (-1=no limit) */

	/* remaining fields may be null; use heap_getattr to read them! */
#ifdef CATALOG_VARLEN			/* variable-length fields start here */
	/* Deprecated: password authority moved to pg_auth_password.  These
	 * fields are kept in sync with the CURRENT (passposition=0) entry in
	 * pg_auth_password as write-through aliases for backward compatibility
	 * with third-party tools that read pg_authid directly.  They will be
	 * removed in a future major release. */
	text		rolpassword;	/* password, if any (deprecated alias) */
	timestamptz rolvaliduntil;	/* password expiration time (deprecated alias) */
#endif
} FormData_pg_authid;

END_CATALOG_STRUCT

/* ----------------
 *		Form_pg_authid corresponds to a pointer to a tuple with
 *		the format of pg_authid relation.
 * ----------------
 */
typedef FormData_pg_authid *Form_pg_authid;

DECLARE_UNIQUE_INDEX(pg_authid_rolname_index, 2676, AuthIdRolnameIndexId, pg_authid, btree(rolname name_ops));
DECLARE_UNIQUE_INDEX_PKEY(pg_authid_oid_index, 2677, AuthIdOidIndexId, pg_authid, btree(oid oid_ops));

MAKE_SYSCACHE(AUTHNAME, pg_authid_rolname_index, 8);
MAKE_SYSCACHE(AUTHOID, pg_authid_oid_index, 8);

#endif							/* PG_AUTHID_H */
