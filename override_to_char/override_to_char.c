/*
 * override_to_char.c
 *
 * Experimental shared library that intercepts to_char(timestamptz, text)
 * (pg_proc OID 1770) by overwriting its slot in the compiled-in
 * fmgr_builtins[] dispatch table.  The replacement prints a NOTICE and then
 * calls the original built-in via the pointer we saved before patching.
 *
 * Context: a temporary hot-patch used to experiment with mitigating
 * CVE-2026-14669.  This is NOT a vetted security fix -- it is a debugging /
 * experimentation aid only.
 *
 * Load into a single session with:  LOAD 'override_to_char';
 * Or patch every backend via shared_preload_libraries.
 *
 * ---------------------------------------------------------------------------
 * RISKS -- read before relying on this for anything.
 *
 * 1. Undefined behavior.  fmgr_builtins[] is defined `const`.  Writing to it
 *    is UB in C regardless of mprotect(): the compiler may assume the table
 *    never changes and constant-fold or cache its contents.
 *
 * 2. Fights W^X / OS hardening.  The table lives in a read-only segment
 *    (.rodata on ELF; __DATA_CONST on Mach-O).  We must mprotect() the page
 *    to PROT_WRITE to patch it.  On hardened-runtime / code-signed builds
 *    (notably macOS) this mprotect() can fail with EACCES or get the process
 *    killed; on such builds this technique simply does not work.
 *
 * 3. Coarse-grained page surgery.  mprotect() changes protection for whole
 *    pages, so neighboring const data (fmgr_builtin_oid_index, other
 *    constants) is momentarily writable too.  We restore PROT_READ right
 *    after the single-pointer write to keep that window minimal.
 *
 * 4. Per-process only.  Each backend is a separate process with its own
 *    mapping of the table.  A LOAD in one session patches only that backend.
 *    To affect all backends the library must be in shared_preload_libraries
 *    so every backend runs _PG_init() and patches its own copy at startup.
 *
 * 5. Stale FmgrInfo caches.  fmgr_info() copies func into finfo->fn_addr.
 *    Any FmgrInfo initialized before we patch keeps the original pointer and
 *    will not be intercepted (matters for long-lived / preloaded lookups).
 *
 * 6. Does not catch DirectFunctionCall.  Only calls that dispatch through
 *    fmgr_info() -> fmgr_builtins[] are intercepted.  C code that calls
 *    timestamptz_to_char() directly, or via DirectFunctionCallN(), bypasses
 *    the table entirely and is unaffected.
 *
 * 7. Only OID 1770.  The other seven to_char() overloads are untouched.
 *
 * 8. No API stability.  This depends on the internal layout and exported
 *    symbols of fmgr_builtins[] / fmgr_builtin_oid_index[]; nothing here is a
 *    supported extension API, and a rebuild or version bump may break it.
 * ---------------------------------------------------------------------------
 */
#include "postgres.h"

#include <sys/mman.h>
#include <unistd.h>

#include "fmgr.h"
#include "utils/builtins.h"
#include "utils/fmgrtab.h"

PG_MODULE_MAGIC;

/* OID of to_char(timestamp with time zone, text); see pg_proc.dat */
#define TO_CHAR_TIMESTAMPTZ_OID 1770

/* Saved pointer to the real built-in, captured before we patch. */
static PGFunction orig_to_char = NULL;

void		_PG_init(void);

/*
 * Flip write protection on the page(s) spanning [ptr, ptr+len).
 *
 * The fmgr_builtins[] table lives in a read-only segment, so we must make it
 * writable before overwriting a slot, and (optionally) restore protection
 * afterwards.  mprotect() operates on whole pages, so this necessarily
 * un-protects neighboring const data for the duration.
 */
static void
set_page_writable(void *ptr, size_t len, bool writable)
{
	long		pagesize = sysconf(_SC_PAGESIZE);
	uintptr_t	start = (uintptr_t) ptr;
	uintptr_t	end = start + len;
	uintptr_t	page_start = start & ~((uintptr_t) pagesize - 1);
	size_t		span = (size_t) (end - page_start);
	int			prot = PROT_READ | (writable ? PROT_WRITE : 0);

	if (mprotect((void *) page_start, span, prot) != 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("override_to_char: mprotect(%s) failed: %m",
						writable ? "RW" : "RO")));
}

/*
 * Replacement implementation installed into the fmgr_builtins[] slot.
 *
 * It receives the same FunctionCallInfo the real built-in would have, prints
 * a message, then dispatches to the saved original pointer.  Calling the
 * pointer directly (rather than via the table) means we do not re-intercept
 * ourselves, so there is no recursion.
 */
static Datum
my_to_char(FunctionCallInfo fcinfo)
{
	/*
	 * to_char(timestamptz, text) is strict, so both args are non-NULL when we
	 * are called; guard anyway to stay safe if that ever changes.
	 */
	if (!PG_ARGISNULL(1))
	{
		char	   *fmt = text_to_cstring(PG_GETARG_TEXT_PP(1));

		ereport(NOTICE,
				(errmsg("override_to_char: intercepted to_char(timestamptz), format=\"%s\"",
						fmt)));
		pfree(fmt);
	}
	else
		ereport(NOTICE,
				(errmsg("override_to_char: intercepted to_char(timestamptz)")));

	return orig_to_char(fcinfo);
}

void
_PG_init(void)
{
	FmgrBuiltin *slot;
	uint16		index;

	if (TO_CHAR_TIMESTAMPTZ_OID > fmgr_last_builtin_oid)
		ereport(ERROR,
				(errmsg("override_to_char: OID %d is not a built-in in this build",
						TO_CHAR_TIMESTAMPTZ_OID)));

	index = fmgr_builtin_oid_index[TO_CHAR_TIMESTAMPTZ_OID];
	if (index == InvalidOidBuiltinMapping)
		ereport(ERROR,
				(errmsg("override_to_char: OID %d has no fmgr_builtins entry",
						TO_CHAR_TIMESTAMPTZ_OID)));

	/* Cast away const: we are deliberately patching the read-only table. */
	slot = (FmgrBuiltin *) &fmgr_builtins[index];

	/* Idempotent: if already patched (e.g. reloaded), do nothing. */
	if (slot->func == my_to_char)
		return;

	orig_to_char = slot->func;

	set_page_writable(&slot->func, sizeof(PGFunction), true);
	slot->func = my_to_char;
	set_page_writable(&slot->func, sizeof(PGFunction), false);

	ereport(LOG,
			(errmsg("override_to_char: patched fmgr_builtins slot for OID %d",
					TO_CHAR_TIMESTAMPTZ_OID)));
}
