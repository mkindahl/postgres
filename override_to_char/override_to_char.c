/*
 * override_to_char.c
 *
 * Experimental shared library that intercepts to_char(timestamptz, text)
 * (pg_proc OID 1770) by overwriting its slot in the compiled-in fmgr_builtins[]
 * dispatch table.  The replacement re-checks the CVE-2026-14669 heap-overflow
 * condition -- an over-long session time zone abbreviation emitted through a
 * TZ/tz format item -- and raises an error instead of calling the vulnerable
 * built-in when that would overflow; otherwise it delegates to the original via
 * the pointer we saved before patching.
 *
 * Context: a temporary hot-patch used to experiment with mitigating
 * CVE-2026-14669.  This is NOT a vetted security fix -- it is a debugging /
 * experimentation aid only.
 *
 * Load into a single session with:  LOAD 'override_to_char'; Or patch every
 * backend via shared_preload_libraries.
 *
 * ---------------------------------------------------------------------------
 * WHY PATCH THE TABLE AT ALL
 *
 * A built-in function cannot be overridden by the usual means.  fmgr_hook is
 * never consulted for built-ins, and editing the pg_proc row has no effect --
 * fmgr_info_cxt_security() resolves a built-in OID straight from
 * fmgr_builtins[] (via the fmgr_isbuiltin() fast path) BEFORE it consults
 * pg_proc or fires any hook.  Overwriting the table slot is the only way to
 * intercept the call without modifying the server.
 * ---------------------------------------------------------------------------
 * DEPLOYMENT
 *
 * This guards the SINK (the to_char call), not the SOURCE (setting the time
 * zone), so it is timing-independent: it checks at call time, regardless of
 * how or when the session time zone was set (SET, ALTER ROLE, or the startup
 * packet).  Consequently it is sound even under session_preload_libraries
 * (e.g. ALTER ROLE ALL SET session_preload_libraries = ...), which needs no
 * restart -- _PG_init runs before any statement, so the patch is always in
 * place before the first to_char().  A SOURCE-side guard (a check_hook on the
 * timezone GUC) does NOT have this property: a timezone delivered in the
 * startup packet is applied before session_preload libraries load, so such a
 * guard must live in shared_preload_libraries (restart required) to be sound.
 * ---------------------------------------------------------------------------
 * RISKS -- read before relying on this for anything.
 *
 * 1. Undefined behavior.  fmgr_builtins[] is defined `const`, and we modify it
 *    through a cast-away-const lvalue.  C11/C17 6.7.3p7 makes that undefined
 *    behavior.
 *
 *    In practice, at a normal non-LTO build the patch works on both compilers.
 *    The read that actually dispatches the call lives in fmgr.c, a separate
 *    translation unit that sees only `extern const FmgrBuiltin
 *    fmgr_builtins[];' with no visible initializer and reads it through a
 *    run-time-computed pointer, so the compiler must emit a real memory load
 *    and cannot fold in the original pointer.  Our store is emitted normally
 *    for the same reason.
 *
 *    The failure mode is real only when the SERVER binary is built with
 *    link-time / whole-program optimization (meson -Db_lto=true, gcc/clang
 *    -flto): then, within the postgres executable, fmgrtab.c's const
 *    initializer becomes visible to fmgr.c's dispatch read, and either compiler
 *    may constant-propagate the original func pointer and drop the load,
 *    silently ignoring our run-time store.  It is the server build that
 *    matters, not this module's: our store sees only the extern declaration, so
 *    LTO on the module cannot fold anything.  PGDG/Debian servers are not built
 *    with LTO (verified: interception fires there); do NOT deploy this against
 *    an LTO-built server binary.
 *
 * 2. Writes to read-only memory -- but only at LOAD time.  fmgr_builtins[]
 *    holds function pointers, so on Linux it lands in .data.rel.ro, which RELRO
 *    (this target is built with full RELRO + BIND_NOW) makes read-only once the
 *    dynamic linker has finished relocations.  We therefore mprotect() the page
 *    to PROT_WRITE before patching and restore PROT_READ immediately after.
 *    The mprotect() is required: without it the store segfaults.
 *
 *    Crucially, mprotect() is called ONLY from _PG_init() (via
 *    set_page_writable), never from the replacement function.  So this happens
 *    only while the library is being loaded; once the load succeeds, every
 *    later to_char() call merely reads the already-patched, read-only slot and
 *    is safe for the life of the process.  A failure at load via LOAD aborts
 *    just that command; a failure at load via shared_preload_libraries is fatal
 *    and the server will not start.
 *
 *    Kernel hardening (mseal) may eventually block this.  Linux 6.10+ has the
 *    mseal() syscall, which can make a mapping's protection immutable; if the
 *    glibc dynamic linker starts sealing RELRO (.data.rel.ro) after applying
 *    it, our mprotect(PROT_WRITE) will return EPERM -- the Linux analog of
 *    macOS __DATA_CONST.  This fails LOUDLY (set_page_writable raises ERROR at
 *    load), not silently, so a broken deployment is obvious immediately.  It is
 *    not active on the PGDG/Debian trixie target (verified: the patch takes
 *    effect there); watch for future glibc/kernel combos that seal RELRO.  The
 *    durable answer when that happens is to run a patched PG minor, not this.
 *
 * 3. Coarse-grained page surgery.  mprotect() changes protection for whole
 *    pages, so neighboring const data (fmgr_builtin_oid_index, other constants)
 *    is momentarily writable too.  We restore PROT_READ right after the
 *    single-pointer write to keep that window minimal.
 *
 * 4. Per-process only.  Each backend is a separate process with its own mapping
 *    of the table.  A LOAD in one session patches only that backend.
 *
 *    Adding the library in shared_preload_libraries and restarting the server
 *    avoids this problem.
 *
 * 5. Stale FmgrInfo caches.  fmgr_info() copies func into finfo->fn_addr. Any
 *    FmgrInfo initialized before we patch keeps the original pointer and will
 *    not be intercepted (matters for long-lived / preloaded lookups).
 *
 *    Adding the library in shared_preload_libraries and restarting the server
 *    avoids this problem.
 *
 * 6. Does not catch DirectFunctionCall.  Only calls that dispatch through
 *    fmgr_info() -> fmgr_builtins[] are intercepted.  C code that calls
 *    timestamptz_to_char() directly, or via DirectFunctionCallN(), bypasses the
 *    table entirely and is unaffected.  Empirically this is moot for OID 1770
 *    in core: grepping src/ and contrib/ finds zero direct callers of
 *    timestamptz_to_char (its only occurrence is its own definition in
 *    formatting.c), so all in-core to_char(timestamptz) calls go through the
 *    table.  Only third-party extension C code could still bypass it.
 *
 * 7. Only OID 1770.  The other seven to_char() overloads are untouched.
 *
 * 8. No API stability.  This depends on the internal layout and exported
 *    symbols of fmgr_builtins[] / fmgr_builtin_oid_index[]; nothing here is a
 *    supported extension API, and a rebuild or version bump may break it.
 *
 *    In practice this layer is very stable.  The FmgrBuiltin field set
 *    (foid, nargs, strict, retset, funcName, func) has not changed since at
 *    least 2004; the layout changed exactly once, a padding-driven member
 *    reorder in 2018 (commit 28d750c0cd5).  Because we access fields by name
 *    and index through the exported arrays -- not by hardcoded offsets -- such
 *    a reorder does not affect us, and PG_MODULE_MAGIC forces a rebuild against
 *    each major's headers anyway, which absorbs any layout change at compile
 *    time.  Note PG_MODULE_MAGIC gates the MAJOR version only (its version
 *    field is PG_VERSION_NUM / 100), so it would not catch a hypothetical
 *    minor-release layout change; the foid check in _PG_init() below guards
 *    that residual case at load time.  The real (still low) risk is not the
 *    struct shape but a semantic
 *    redesign of built-in dispatch itself: the fmgr_isbuiltin fast path
 *    (~unchanged for 20 years) or the fmgr_builtin_oid_index lookup array
 *    (added 2017, stable since).  No such change is on the horizon.
 * ---------------------------------------------------------------------------
 */
#include <postgres.h>

#include <sys/mman.h>
#include <unistd.h>

#include "fmgr.h"
#include "pgtime.h"
#include "varatt.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/fmgrtab.h"
#include "utils/timestamp.h"

PG_MODULE_MAGIC;

/*
 * Mirror of formatting.c internals used to size the to_char() output buffer.
 * These are file-static there and not exported, so we redefine them.
 *
 * The buffer reserves DCH_MAX_ITEM_SIZ bytes per format character, and the
 * TZ/tz format items have a keyword length of 2. The abbreviation must fit in
 * DCH_TZ_RESERVED bytes.
 */
#define DCH_MAX_ITEM_SIZ 12UL
#define DCH_TZ_KEYLEN 2UL
#define DCH_TZ_RESERVED (DCH_TZ_KEYLEN * DCH_MAX_ITEM_SIZ)

/* Saved pointer to the real built-in, captured before we patch. */
static PGFunction orig_to_char = NULL;

void _PG_init(void);

/*
 * Flip write protection on the page(s) spanning [ptr, ptr+len).
 *
 * On Linux fmgr_builtins[] lives in .data.rel.ro, which RELRO marks read-only
 * after relocation, so we must make it writable before overwriting a slot and
 * restore protection afterwards.  mprotect() operates on whole pages, so this
 * necessarily un-protects neighboring const data for the duration.
 */
static void
set_page_writable(void *ptr, size_t len, bool writable)
{
	long pagesize = sysconf(_SC_PAGESIZE);
	uint8 *start = ptr;
	uint8 *end = start + len;
	uint8 *page_start = (uint8 *)((uintptr_t)start & ~((uintptr_t)pagesize - 1));
	size_t span = end - page_start;
	int prot = PROT_READ | (writable ? PROT_WRITE : 0);

	if (mprotect(page_start, span, prot) != 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("mprotect(%s) failed: %m",
						writable ? "RW" : "RO")));
}

/*
 * Does the format string contain a TZ or tz item (the only ones that emit the
 * time zone abbreviation)?  We scan for an adjacent 't'/'T' followed by
 * 'z'/'Z'.  This deliberately over-approximates and matches, for example,
 * TZH/TZM (which emit only a numeric offset and are safe) and a quoted literal
 * "tz". Over-matching only means we might reject a call that a fully faithful
 * parser would allow, and only ever when the abbreviation is already
 * pathologically long (> DCH_TZ_RESERVED bytes).  It never misses a real TZ/tz
 * item, so it never lets an overflow through.
 */
static bool
format_uses_tz(const char *fmtstr)
{
	for (const char *p = fmtstr; p[0] != '\0' && p[1] != '\0'; p++)
		if (toupper(p[0]) == 'T' && toupper(p[1]) == 'Z')
			return true;
	return false;
}

/*
 * Replacement implementation installed into the fmgr_builtins[] slot.
 *
 * It receives the same FunctionCallInfo the real built-in would have.  It
 * reproduces the time zone abbreviation exactly as timestamptz_to_char() does
 * (timestamp2tm with the session time zone), and if that abbreviation is too
 * long to fit the space to_char() reserves for a TZ item AND the format string
 * actually uses a TZ/tz item, it raises the same error the upstream fix raises
 * BEFORE calling the vulnerable code.
 *
 * Otherwise it dispatches to the saved original pointer.  Calling that pointer
 * directly (rather than via the table) means we do not re-intercept ourselves,
 * so there is no recursion.
 */
static Datum
safe_to_char(FunctionCallInfo fcinfo)
{
	TimestampTz dt;
	text *fmt;
	int tz;
	struct pg_tm tt;
	fsec_t fsec;
	const char *tzn = NULL;
	char *fmtstr;
	bool uses_tz;

	/* Function to_char(timestamptz, text) is strict, but we're defensive. */
	if (PG_ARGISNULL(0) || PG_ARGISNULL(1))
		return orig_to_char(fcinfo);

	/*
	 * We fetch these after the check above since they otherwise would
	 * dereference data that is not dereferenceable.
	 */
	dt = PG_GETARG_TIMESTAMP(0);
	fmt = PG_GETARG_TEXT_PP(1);

	/*
	 * An empty format or a non-finite timestamp never reaches the time zone
	 * code in to_char(), so those cases are always safe to delegate.
	 */
	if (VARSIZE_ANY_EXHDR(fmt) <= 0 || TIMESTAMP_NOT_FINITE(dt))
		return orig_to_char(fcinfo);

	/*
	 * Resolve the abbreviation the same way the real function will.  On failure
	 * just delegate and let to_char() raise its own "timestamp out of range".
	 */
	if (timestamp2tm(dt, &tz, &tt, &fsec, &tzn, NULL) != 0)
		return orig_to_char(fcinfo);

	fmtstr = text_to_cstring(fmt);
	uses_tz = format_uses_tz(fmtstr);
	pfree(fmtstr);

	if (tzn != NULL && strlen(tzn) > DCH_TZ_RESERVED && uses_tz)
		ereport(ERROR,
				(errcode(ERRCODE_DATETIME_VALUE_OUT_OF_RANGE),
				 errmsg("time zone format value too long")));

	return orig_to_char(fcinfo);
}

void _PG_init(void)
{
	FmgrBuiltin *slot;
	uint16 index;

	if (F_TO_CHAR_TIMESTAMPTZ_TEXT > fmgr_last_builtin_oid)
		ereport(ERROR,
				(errmsg("OID %d is not a built-in in this build",
						F_TO_CHAR_TIMESTAMPTZ_TEXT)));

	index = fmgr_builtin_oid_index[F_TO_CHAR_TIMESTAMPTZ_TEXT];
	if (index == InvalidOidBuiltinMapping)
		ereport(ERROR,
				(errmsg("OID %d has no fmgr_builtins entry",
						F_TO_CHAR_TIMESTAMPTZ_TEXT)));

	/* Cast away const: we are deliberately patching the read-only table. */
	slot = (FmgrBuiltin *)&fmgr_builtins[index];

	/*
	 * Sanity check the oid_index -> fmgr_builtins mapping before we overwrite
	 * anything: the slot must actually describe OID F_TO_CHAR_TIMESTAMPTZ_TEXT.
	 * PG_MODULE_MAGIC already gates the major-version ABI, but this additionally
	 * guards against a forked or rebuilt table whose layout shifted the entry.
	 */
	if (slot->foid != F_TO_CHAR_TIMESTAMPTZ_TEXT)
		ereport(ERROR,
				(errmsg("override_to_char: fmgr_builtins[%u] describes OID %u, expected %d",
						index, slot->foid, F_TO_CHAR_TIMESTAMPTZ_TEXT)));

	/* Idempotent: if already patched (e.g. reloaded), do nothing. */
	if (slot->func != safe_to_char)
	{
		orig_to_char = slot->func;

		set_page_writable(&slot->func, sizeof(PGFunction), true);
		slot->func = safe_to_char;
		set_page_writable(&slot->func, sizeof(PGFunction), false);
	}
}
