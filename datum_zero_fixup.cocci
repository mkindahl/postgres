@@
typedef Datum;
symbol UndefinedDatum;
@@
- (Datum) 0
+ UndefinedDatum

@@
typedef Datum;
identifier F;
@@
  Datum F(...) {
  ... when any
(
- return (Datum) 0;
+ return UndefinedDatum;
|
- return 0;
+ return UndefinedDatum;
)
  ... }

@@
typedef Datum;
identifier v;
@@
- Datum v = 0;
+ Datum v = UndefinedDatum;

@@
typedef Datum;
idexpression Datum v;
@@
- v = 0
+ v = UndefinedDatum

@@
identifier func = {before_shmem_exit, on_shmem_exit, on_proc_exit, ShutdownXLOG};
@@
  func(...,
- 0
+ UndefinedDatum
  );

@@
identifier func = {set_stats_slot};
expression list [6] Es;
expression E7,E8,E9,E10;
@@
  func(Es,
(
- 0
+ UndefinedDatum
|
  E7
)
  ,E8,
(
- 0
+ UndefinedDatum
|
E9
)
  , E10)
