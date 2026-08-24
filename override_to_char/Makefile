MODULE_big = override_to_char
OBJS = override_to_char.o
PGFILEDESC = "override_to_char - intercept to_char(timestamptz) via fmgr_builtins patch"

# Point this at the pg_config for the server you want to load the module into.
# For an in-tree build, e.g.:
#   make PG_CONFIG=/path/to/build/bin/pg_config install
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
