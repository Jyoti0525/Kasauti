"""Every module that declares a table, imported so :data:`kasauti.db.schema.Base.metadata` is
complete. Alembic's autogenerate and the drift test in ``tests/db`` read the metadata through
this module; a table left out of it would show up there as one to drop."""

from __future__ import annotations

import kasauti.jobs.table  # noqa: F401 - registers `jobs`
from kasauti.db.schema import Base

metadata = Base.metadata
