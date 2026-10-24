#!/usr/bin/env python3
"""Generate the golden Apache Iceberg tables under this directory.

The tables are written by pyiceberg (the reference Python implementation) and
committed as golden fixtures for the Maskura Iceberg table-format adapter
(ADR 0028). They exercise format-version 1 and 2 metadata, partitioned and
unpartitioned layouts, multiple retained snapshots, tables with no snapshots,
and a merge-on-read table carrying delete files (which the adapter must fail
closed on).

Regeneration (this directory as CWD):

    uv venv .venv
    uv pip install --python .venv/bin/python pyiceberg pyarrow sqlalchemy
    .venv/bin/python generate_fixtures.py

Layout note: every table location is `s3://bucket/<fixture-name>` and every
referenced file URI is `s3://bucket/<fixture-name>/...`, so the fixtures can be
loaded into an object store at the same keys without rewriting any bytes. The
`FakeS3FileIO` below is a generator-side stand-in that stores those URIs under
`./_warehouse/`, which is discarded after generation.

`metadata/version-hint.text` — the Hadoop-style version pointer the Iceberg
commit protocol (and Maskura's commit) updates atomically — is written by
this script: pyiceberg's SQL catalog tracks the pointer in the catalog
service instead. The `v2_partitioned` fixture deliberately carries none so
detection is pinned with and without the pointer.

Snapshot ids, table uuids, and timestamps are generated fresh on each run;
regenerating the fixtures rewrites the files.
"""

from __future__ import annotations

import pathlib
import shutil
from datetime import date
import sys


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import pyarrow as pa  # noqa: E402
from fake_s3_io import FakeS3FileIO  # noqa: E402
from pyiceberg.catalog.sql import SqlCatalog  # noqa: E402
from pyiceberg.io import InputFile, OutputFile  # noqa: E402
from pyiceberg.partitioning import PartitionField, PartitionSpec  # noqa: E402
from pyiceberg.schema import Schema  # noqa: E402
from pyiceberg.transforms import DayTransform, IdentityTransform  # noqa: E402
from pyiceberg.types import (  # noqa: E402
    DateType,
    LongType,
    NestedField,
    StringType,
)

HERE = pathlib.Path(__file__).resolve().parent
WAREHOUSE_ROOT = HERE / "_warehouse"
CATALOG_DB = HERE / "_catalog.sqlite"
BUCKET_URI = "s3://bucket"


def _frame(fields, arrays):
    return pa.table(arrays, schema=pa.schema(fields))


ID = pa.field("id", pa.int64(), nullable=False)
EMAIL = pa.field("email", pa.string())
NOTE = pa.field("note", pa.string())
CATEGORY = pa.field("category", pa.string())
EVENT_DATE = pa.field("event_date", pa.date32())


def rows_1(**columns):
    return _frame([ID, EMAIL, NOTE, CATEGORY], columns)


def rows_2(**columns):
    return _frame([ID, EMAIL, CATEGORY, EVENT_DATE], columns)


def rows_3(**columns):
    return _frame([ID, EMAIL, CATEGORY], columns)


def rows_4(**columns):
    return _frame([ID, EMAIL], columns)


def make_catalog() -> SqlCatalog:
    WAREHOUSE_ROOT.mkdir(exist_ok=True)
    return SqlCatalog(
        "default",
        uri=f"sqlite:///{CATALOG_DB}",
        warehouse=BUCKET_URI,
        **{"py-io-impl": "fake_s3_io.FakeS3FileIO"},
    )


def copy_out(name: str, with_version_hint: bool) -> None:
    src = WAREHOUSE_ROOT / name
    dst = HERE / name
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)
    if with_version_hint:
        # pyiceberg's SQL catalog tracks the pointer in the catalog service,
        # so the Hadoop-style version pointer is written here (it is the file
        # the Iceberg commit protocol — and Maskura's commit — updates
        # atomically).
        version = max(
            int(path.name.split("-")[0])
            for path in (dst / "metadata").glob("*.metadata.json")
        )
        (dst / "metadata" / "version-hint.text").write_text(
            f"{version}\n", encoding="utf-8"
        )
    print(f"wrote {name}")


def build_v1_unpartitioned(catalog: SqlCatalog) -> None:
    name = "v1_unpartitioned"
    schema = Schema(
        NestedField(1, "id", LongType(), required=True),
        NestedField(2, "email", StringType(), required=False),
        NestedField(3, "note", StringType(), required=False),
        NestedField(4, "category", StringType(), required=False),
    )
    table = catalog.create_table(
        ("f", name), schema, location=f"{BUCKET_URI}/{name}", properties={"format-version": "1"}
    )
    table.append(
        rows_1(
            id=pa.array([1, 2, 3, 4], pa.int64()),
            email=pa.array(
                ["ada@example.com", "bob@example.com", None, "cid@example.com"],
                pa.string(),
            ),
            note=pa.array([None, "keep", "secret-note", None], pa.string()),
            category=pa.array(["alpha", "alpha", "beta", None], pa.string()),
        )
    )
    copy_out(name, with_version_hint=True)


def build_v2_partitioned(catalog: SqlCatalog) -> None:
    name = "v2_partitioned"
    schema = Schema(
        NestedField(1, "id", LongType(), required=True),
        NestedField(2, "email", StringType(), required=False),
        NestedField(3, "category", StringType(), required=False),
        NestedField(4, "event_date", DateType(), required=False),
    )
    spec = PartitionSpec(
        PartitionField(source_id=3, field_id=1000, transform=IdentityTransform(), name="category"),
        PartitionField(source_id=4, field_id=1001, transform=DayTransform(), name="event_date_day"),
    )
    table = catalog.create_table(
        ("f", name), schema, location=f"{BUCKET_URI}/{name}", partition_spec=spec
    )
    table.append(
        rows_2(
            id=pa.array([10, 11], pa.int64()),
            email=pa.array(["x@example.com", "y@example.com"], pa.string()),
            category=pa.array(["alpha", "beta"], pa.string()),
            event_date=pa.array(
                [date(2024, 1, 1), date(2024, 1, 2)], pa.date32()
            ),
        )
    )
    table.append(
        rows_2(
            id=pa.array([12, 13], pa.int64()),
            email=pa.array(["z@example.com", "w@example.com"], pa.string()),
            category=pa.array(["alpha", "gamma"], pa.string()),
            event_date=pa.array(
                [date(2024, 1, 1), date(2024, 2, 1)], pa.date32()
            ),
        )
    )
    # Deliberately no version-hint.text: detection must work without it.
    copy_out(name, with_version_hint=False)


def build_v2_multi_snapshot(catalog: SqlCatalog) -> None:
    name = "v2_multi_snapshot"
    schema = Schema(
        NestedField(1, "id", LongType(), required=True),
        NestedField(2, "email", StringType(), required=False),
        NestedField(3, "category", StringType(), required=False),
    )
    spec = PartitionSpec(
        PartitionField(source_id=3, field_id=1000, transform=IdentityTransform(), name="category"),
    )
    table = catalog.create_table(
        ("f", name), schema, location=f"{BUCKET_URI}/{name}", partition_spec=spec
    )
    table.append(
        rows_3(
            id=pa.array([1, 2], pa.int64()),
            email=pa.array(["m1@example.com", "m2@example.com"], pa.string()),
            category=pa.array(["red", "red"], pa.string()),
        )
    )
    table.append(
        rows_3(
            id=pa.array([3, 4], pa.int64()),
            email=pa.array(["m3@example.com", "m4@example.com"], pa.string()),
            category=pa.array(["blue", "blue"], pa.string()),
        )
    )
    # Copy-on-write overwrite: keeps one file, tombstones another, adds one.
    table.overwrite(
        rows_3(
            id=pa.array([2, 5], pa.int64()),
            email=pa.array(["m2@example.com", "m5@example.com"], pa.string()),
            category=pa.array(["red", "green"], pa.string()),
        ),
        overwrite_filter="category = 'red'",
    )
    copy_out(name, with_version_hint=True)


def build_v2_empty(catalog: SqlCatalog) -> None:
    name = "v2_empty"
    schema = Schema(
        NestedField(1, "id", LongType(), required=True),
        NestedField(2, "email", StringType(), required=False),
    )
    catalog.create_table(("f", name), schema, location=f"{BUCKET_URI}/{name}")
    copy_out(name, with_version_hint=True)


def build_v2_delete_files(catalog: SqlCatalog) -> None:
    name = "v2_delete_files"
    schema = Schema(
        NestedField(1, "id", LongType(), required=True),
        NestedField(2, "email", StringType(), required=False),
    )
    table = catalog.create_table(
        ("f", name),
        schema,
        location=f"{BUCKET_URI}/{name}",
    )
    table.append(
        rows_4(
            id=pa.array([1, 2, 3], pa.int64()),
            email=pa.array(
                ["d1@example.com", "d2@example.com", "d3@example.com"], pa.string()
            ),
        )
    )
    # pyiceberg 0.12 does not implement merge-on-read writes (`delete()` falls
    # back to copy-on-write), so the position-delete file is written here in the
    # spec's delete-file layout and appended through pyiceberg's own snapshot
    # API. This produces the merge-on-read manifest shape (`data_file.content
    # == 1`) the adapter must fail closed on.
    import pyarrow.parquet as pq
    from pyiceberg.conversions import to_bytes
    from pyiceberg.manifest import DataFile, DataFileContent, FileFormat
    from pyiceberg.typedef import Record

    delete_path = f"{BUCKET_URI}/{name}/data/00000-0-deletes.parquet"
    delete_target = WAREHOUSE_ROOT / name / "data" / "00000-0-deletes.parquet"
    delete_target.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(
        pa.table(
            {
                "file_path": pa.array(
                    [f"{BUCKET_URI}/{name}/data/00000-0-03a5806f.parquet"], pa.string()
                ),
                "pos": pa.array([1], pa.int64()),
            }
        ),
        delete_target,
    )
    delete_file = DataFile.from_args(
        content=DataFileContent.POSITION_DELETES,
        file_path=delete_path,
        file_format=FileFormat.PARQUET,
        partition=Record(),
        record_count=1,
        file_size_in_bytes=delete_target.stat().st_size,
        column_sizes={2: 40, 3: 40},
        value_counts={2: 1, 3: 1},
        null_value_counts={2: 0, 3: 0},
        nan_value_counts={},
        lower_bounds={3: to_bytes(schema.find_field(1).field_type, 1)},
        upper_bounds={3: to_bytes(schema.find_field(1).field_type, 1)},
        sort_order_id=None,
        equality_ids=None,
        key_metadata=None,
        split_offsets=None,
        spec_id=table.metadata.default_spec_id,
    )
    with table.transaction() as tx:
        with tx.update_snapshot().fast_append() as append:
            append.append_data_file(delete_file)
    copy_out(name, with_version_hint=True)


def main() -> None:
    for path in (CATALOG_DB,):
        if path.exists():
            path.unlink()
    if WAREHOUSE_ROOT.exists():
        shutil.rmtree(WAREHOUSE_ROOT)
    catalog = make_catalog()
    catalog.create_namespace("f")
    build_v1_unpartitioned(catalog)
    build_v2_partitioned(catalog)
    build_v2_multi_snapshot(catalog)
    build_v2_empty(catalog)
    build_v2_delete_files(catalog)
    shutil.rmtree(WAREHOUSE_ROOT, ignore_errors=True)
    CATALOG_DB.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
