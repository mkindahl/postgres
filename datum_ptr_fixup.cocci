@@
expression lhs, rhs;
binary operator OP;
@@
- PointerGetDatum(lhs) OP rhs
+ lhs OP DatumGetVoidPointer(rhs)
