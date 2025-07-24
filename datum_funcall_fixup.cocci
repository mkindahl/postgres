@r1@
typedef Oid;
typedef FmgrInfo;
identifier FuncCall = {FunctionCall1};
expression E;
position P;
FmgrInfo *I;
@@
* FuncCall(I, E@P)

@script:python@
P << r1.P;
E << r1.E;
@@
coccilib.report.print_report(P[0], f"Expression is {E}")
coccilib.report.print_report(P[0], f"Fields are {dir(E)}")
