// Since PG16 there are array versions of common palloc operations, so
// we can use those instead.
//
// We ignore cases where we have a anonymous struct and also when the
// type of the variable being assigned to is different from the
// inferred type.

virtual patch
virtual report
virtual context

// These rules (soN) are needed to rewrite types of the form
// sizeof(T[C]) to C * sizeof(T) since Cocci cannot (currently) handle
// it.
@initialize:python@
@@
import re

CRE = re.compile(r'(.*)\s+\[\s+(\d+)\s+\]$')

def is_array_type(s):
    mre = CRE.match(s)
    return (mre is not None)

@so1 depends on patch@
type T : script:python() {  is_array_type(T) };
@@
palloc(sizeof(T))

@script:python so2 depends on patch@
T << so1.T;
T2;
E;
@@
mre = CRE.match(T)
coccinelle.T2 = cocci.make_type(mre.group(1))
coccinelle.E = cocci.make_expr(mre.group(2))

@depends on patch@
type so1.T;
type so2.T2;
expression so2.E;
@@
- palloc(sizeof(T))
+ palloc(E * sizeof(T2))

@r1 depends on report || context@
type T !~ "^struct {";
expression E;
position p;
@@
* palloc@p(E * sizeof(T))

@script:python depends on report@
p << r1.p;
@@
coccilib.report.print_report(p[0], "palloc can be replaced with palloc_array")

@depends on patch@
type T !~ "^struct {";
expression E;
T *P;
constant C;
@@
(
- (T*) palloc(E * sizeof( \( *P \| P[C] \) ))
+ palloc_array(T, E)
|
- (T*) palloc(E * sizeof(T))
+ palloc_array(T, E)
|
- palloc(E * sizeof( \( *P \| P[C] \) ))
+ palloc_array(T, E)
|
- palloc(E * sizeof(T))
+ palloc_array(T, E)
)

@r2 depends on report || context@
type T;
expression E;
position p;
@@
* palloc0@p(E * sizeof(T))

@script:python depends on report@
p << r1.p;
@@
coccilib.report.print_report(p[0], "this palloc0 can be replaced with palloc0_array")

@depends on patch@
type T !~ "^struct {";
expression E;
T *P;
constant C;
@@
(
- (T*) palloc0(E * sizeof( \( *P \| P[C] \) ))
+ palloc0_array(T, E)
|
- (T*) palloc0(E * sizeof(T))
+ palloc0_array(T, E)
|
- palloc0(E * sizeof( \( *P \| P[C] \) ))
+ palloc0_array(T, E)
|
- palloc0(E * sizeof(T))
+ palloc0_array(T, E)
)

@r3 depends on report || context@
type T !~ "^struct {";
expression E;
idexpression T *P;
position p;
@@
* repalloc@p(P, E * sizeof(T))

@script:python depends on report@
p << r3.p;
@@
coccilib.report.print_report(p[0], "this repalloc can be replaced with repalloc_array")

@depends on patch@
type T !~ "^struct {";
expression E;
idexpression T *P1;
idexpression T *P2;
constant C;
@@
(
- (T*) repalloc(P1, E * sizeof( \( *P2 \| P2[C] \) ))
+ repalloc_array(P1, T, E)
|
- (T*) repalloc(P1, E * sizeof(T))
+ repalloc_array(P1, T, E)
|
- repalloc(P1, E * sizeof( \( *P2 \| P2[C] \) ))
+ repalloc_array(P1, T, E)
|
- repalloc(P1, E * sizeof(T))
+ repalloc_array(P1, T, E)
)

@r4 depends on report || context@
type T !~ "^struct {";
position p;
@@
* palloc@p(sizeof(T))

@script:python depends on report@
p << r4.p;
@@
coccilib.report.print_report(p[0], "this palloc can be replaced with palloc_object")

@depends on patch@
type T !~ "^struct {";
T* P;
constant C;
@@
(
- (T*) palloc(sizeof( \( *P \| P[C] \) ))
+ palloc_object(T)
|
- (T*) palloc(sizeof(T))
+ palloc_object(T)
|
- palloc(sizeof( \( *P \| P[C] \) ))
+ palloc_object(T)
|
- palloc(sizeof(T))
+ palloc_object(T)
)

@r5 depends on report || context@
type T !~ "^struct {";
position p;
@@
* palloc0@p(sizeof(T))

@script:python depends on report@
p << r5.p;
@@
coccilib.report.print_report(p[0], "this palloc0 can be replaced with palloc0_object")

@depends on patch@
type T !~ "^struct {";
T *P;
constant C;
@@
(
- (T*) palloc0(sizeof( \( *P \| P[C] \) ))
+ palloc0_object(T)
|
- (T*) palloc0(sizeof(T))
+ palloc0_object(T)
|
- palloc0(sizeof( \( *P \| P[C] \) ))
+ palloc0_object(T)
|
- palloc0(sizeof(T))
+ palloc0_object(T)
)
