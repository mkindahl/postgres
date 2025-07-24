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

