// Replace uses of StringInfo with StringInfoData where the info is
// dynamically allocated but (optionally) freed at the end of the
// block. This will avoid one dynamic allocation that otherwise have
// to be dealt with.
//
// For example, this code:
//
//    StringInfo info = makeStringInfo();
//    ...
//    appendStringInfo(info, ...);
//    ...
//    return info->data;
//
// Can be replaced with:
//
//    StringInfoData info;
//    initStringInfo(&info);
//    ...
//    appendStringInfo(&info, ...);
//    ...
//    return info.data;

virtual report
virtual context
virtual patch

// This matches local idexpressions both in declarations and as
// statements.
@idexpr@
typedef StringInfo;
local idexpression StringInfo info;
position p;
expression E;
statement S;
@@
  info@p = makeStringInfo()
  ... when != info->data = E
      when != info = E
      when != return info;
      when != while (...) S
  
@depends on context exists@
identifier info;
position idexpr.p;
@@
* StringInfo info;
  ...
* info@p = makeStringInfo();
      
@depends on context exists@
identifier info;
position idexpr.p;
@@
* StringInfo info@p = makeStringInfo();
      
@script:python depends on report@
p << idexpr.p;
@@
coccilib.report.print_report(p[0], "StringInfoData can be used here")

@depends on patch exists@
identifier info, fld;
position idexpr.p;
@@
(
- StringInfo info@p = makeStringInfo();
+ StringInfoData info;
  <... D ...>
+ initStringInfo(&info);
  S
|
- StringInfo info;
+ StringInfoData info;
  ...
- info@p = makeStringInfo();
+ initStringInfo(&info);
)
  ... when any
(
- info->fld
+ info.fld
|
- info
+ &info
)
  <...
- destroyStringInfo(info);
  ...>
