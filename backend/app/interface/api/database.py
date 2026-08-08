"""
Admin database browser — introspection + CRUD for all PostgreSQL tables.
Provides table list, column metadata, paginated row data, stats, and write operations.
"""
import re
import logging
from typing import Any, Optional, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Query, Body, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import text, inspect as sa_inspect, func

from ...db import get_db, engine
from ...admin_auth import get_current_admin

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/admin/database", tags=["admin-database"])


def _validate_table(inspector, table_name: str) -> set:
    """Validate table exists, return all valid table names."""
    valid_tables = set(inspector.get_table_names(schema="public"))
    if table_name not in valid_tables:
        raise HTTPException(status_code=404, detail=f"Table '{table_name}' not found")
    return valid_tables


def _get_pk_column(inspector, table_name: str) -> str:
    """Get primary key column name for a table."""
    pk = inspector.get_pk_constraint(table_name, "public")
    pk_cols = pk.get("constrained_columns", []) if pk else []
    if not pk_cols:
        raise HTTPException(status_code=400, detail=f"Table '{table_name}' has no primary key — cannot perform row operations")
    return pk_cols[0]


def _serialize_value(v):
    """Serialize a database value to JSON-compatible format."""
    if v is None:
        return None
    elif isinstance(v, (str, int, float, bool)):
        return v
    elif isinstance(v, dict):
        return v
    elif isinstance(v, list):
        return v
    else:
        return str(v)


# ── Global database statistics ────────────────────────────────────────

@router.get("/stats")
async def database_stats(request: Request, db: Session = Depends(get_db), admin=Depends(get_current_admin)):
    """Comprehensive database statistics: sizes, connections, bloat, activity."""
    stats = {}

    # Database size
    try:
        row = db.execute(text("SELECT pg_database_size(current_database()) as size")).mappings().first()
        stats["database_size_bytes"] = row["size"] if row else 0
        stats["database_size_human"] = _human_size(row["size"]) if row else "0 B"
    except Exception:
        stats["database_size_bytes"] = 0
        stats["database_size_human"] = "N/A"

    # Database name & version
    try:
        row = db.execute(text("SELECT current_database(), version()")).mappings().first()
        stats["database_name"] = row["current_database"]
        stats["postgres_version"] = row["version"]
    except Exception:
        stats["database_name"] = "N/A"
        stats["postgres_version"] = "N/A"

    # Active connections
    try:
        row = db.execute(text(
            "SELECT count(*) as total, "
            "count(*) FILTER (WHERE state = 'active') as active, "
            "count(*) FILTER (WHERE state = 'idle') as idle "
            "FROM pg_stat_activity WHERE datname = current_database()"
        )).mappings().first()
        stats["connections"] = {
            "total": row["total"],
            "active": row["active"],
            "idle": row["idle"],
        }
    except Exception:
        stats["connections"] = {"total": 0, "active": 0, "idle": 0}

    # Max connections
    try:
        row = db.execute(text("SHOW max_connections")).mappings().first()
        stats["max_connections"] = int(row["max_connections"])
    except Exception:
        stats["max_connections"] = 100

    # Table stats from pg_stat_user_tables
    inspector = sa_inspect(engine)
    table_names = sorted(inspector.get_table_names(schema="public"))

    table_stats = []
    total_rows = 0
    for tname in table_names:
        try:
            count = db.execute(text(f'SELECT COUNT(*) FROM "{tname}"')).scalar() or 0
        except Exception:
            count = 0
        total_rows += count

        # Table size from pg_total_relation_size
        try:
            size_row = db.execute(
                text("SELECT pg_total_relation_size(:tbl) as total_size, "
                     "pg_relation_size(:tbl) as data_size, "
                     "pg_indexes_size(:tbl) as index_size"),
                {"tbl": f"public.{tname}"}
            ).mappings().first()
            total_size = size_row["total_size"] or 0
            data_size = size_row["data_size"] or 0
            index_size = size_row["index_size"] or 0
        except Exception:
            total_size = data_size = index_size = 0

        columns = inspector.get_columns(tname, schema="public")
        pk_cols = inspector.get_pk_constraint(tname, "public")
        pk_names = pk_cols.get("constrained_columns", []) if pk_cols else []
        indexes = inspector.get_indexes(tname, "public")

        # Sequential vs index scans
        try:
            scan_row = db.execute(text(
                "SELECT seq_scan, idx_scan, n_tup_ins, n_tup_upd, n_tup_del, "
                "n_live_tup, n_dead_tup, last_vacuum, last_autovacuum "
                "FROM pg_stat_user_tables WHERE relname = :tname"
            ), {"tname": tname}).mappings().first()
        except Exception:
            scan_row = None

        table_stats.append({
            "name": tname,
            "row_count": count,
            "column_count": len(columns),
            "primary_keys": pk_names,
            "index_count": len(indexes),
            "total_size_bytes": total_size,
            "total_size_human": _human_size(total_size),
            "data_size_bytes": data_size,
            "data_size_human": _human_size(data_size),
            "index_size_bytes": index_size,
            "index_size_human": _human_size(index_size),
            "seq_scans": scan_row["seq_scan"] if scan_row else 0,
            "idx_scans": scan_row["idx_scan"] if scan_row else 0,
            "inserts": scan_row["n_tup_ins"] if scan_row else 0,
            "updates": scan_row["n_tup_upd"] if scan_row else 0,
            "deletes": scan_row["n_tup_del"] if scan_row else 0,
            "live_tuples": scan_row["n_live_tup"] if scan_row else count,
            "dead_tuples": scan_row["n_dead_tup"] if scan_row else 0,
            "last_vacuum": str(scan_row["last_vacuum"]) if scan_row and scan_row["last_vacuum"] else None,
            "last_autovacuum": str(scan_row["last_autovacuum"]) if scan_row and scan_row["last_autovacuum"] else None,
        })

    stats["total_tables"] = len(table_names)
    stats["total_rows"] = total_rows
    stats["tables"] = table_stats

    # Recent activity (slow queries placeholder)
    try:
        row = db.execute(text(
            "SELECT count(*) as long_running "
            "FROM pg_stat_activity "
            "WHERE state = 'active' AND now() - query_start > interval '5 seconds' "
            "AND datname = current_database()"
        )).mappings().first()
        stats["slow_queries"] = row["long_running"] if row else 0
    except Exception:
        stats["slow_queries"] = 0

    return stats


def _human_size(size_bytes: int) -> str:
    """Convert bytes to human-readable string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 ** 3:
        return f"{size_bytes / (1024 ** 2):.1f} MB"
    else:
        return f"{size_bytes / (1024 ** 3):.2f} GB"


# ── Table list with row counts ──────────────────────────────────────

@router.get("/tables")
async def list_tables(request: Request, db: Session = Depends(get_db), admin=Depends(get_current_admin)):
    """Return all user tables with their row counts and sizes."""
    inspector = sa_inspect(engine)

    # Get actual table names from the public schema
    table_names = sorted(inspector.get_table_names(schema="public"))

    result = []
    for tname in table_names:
        # Row count (fast estimate for Postgres)
        try:
            count = db.execute(text(f'SELECT COUNT(*) FROM "{tname}"')).scalar() or 0
        except Exception:
            count = 0

        # Column count
        columns = inspector.get_columns(tname, schema="public")
        pk_cols = inspector.get_pk_constraint(tname, schema="public")
        pk_names = pk_cols.get("constrained_columns", []) if pk_cols else []

        # Index count
        indexes = inspector.get_indexes(tname, schema="public")

        result.append({
            "name": tname,
            "row_count": count,
            "column_count": len(columns),
            "primary_keys": pk_names,
            "index_count": len(indexes),
        })

    return result


# ── Column metadata for a specific table ─────────────────────────────

@router.get("/tables/{table_name}/columns")
async def table_columns(request: Request, table_name: str, db: Session = Depends(get_db), admin=Depends(get_current_admin)):
    """Return column metadata for a given table."""
    inspector = sa_inspect(engine)

    # Validate table exists (prevent SQL injection)
    valid_tables = set(inspector.get_table_names(schema="public"))
    if table_name not in valid_tables:
        raise HTTPException(status_code=404, detail=f"Table '{table_name}' not found")

    columns = inspector.get_columns(table_name, schema="public")
    pk_cols = inspector.get_pk_constraint(table_name, schema="public")
    pk_names = set(pk_cols.get("constrained_columns", []) if pk_cols else [])
    indexes = inspector.get_indexes(table_name, schema="public")

    # Build index lookup
    index_map = {}
    for idx in indexes:
        for col in idx.get("column_names", []):
            index_map.setdefault(col, []).append(idx["name"])

    result = []
    for col in columns:
        col_name = col["name"]
        result.append({
            "name": col_name,
            "type": str(col["type"]),
            "nullable": col.get("nullable", True),
            "primary_key": col_name in pk_names,
            "default": str(col["default"]) if col.get("default") else None,
            "indexes": index_map.get(col_name, []),
        })

    return result


# ── Paginated row data ───────────────────────────────────────────────

@router.get("/tables/{table_name}/rows")
async def table_rows(
    request: Request,
    table_name: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    search: Optional[str] = Query(None),
    sort_by: Optional[str] = Query(None),
    sort_dir: str = Query("desc", pattern="^(asc|desc)$"),
    tenant_filter: Optional[str] = Query(None, description="Filter by tenant_id"),
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    """Return paginated rows for a table with optional text search across all columns."""
    inspector = sa_inspect(engine)

    # Validate table exists
    valid_tables = set(inspector.get_table_names(schema="public"))
    if table_name not in valid_tables:
        raise HTTPException(status_code=404, detail=f"Table '{table_name}' not found")

    # Get columns for this table
    columns = inspector.get_columns(table_name, schema="public")
    col_names = [c["name"] for c in columns]

    # Validate sort column
    if sort_by and sort_by not in col_names:
        raise HTTPException(status_code=400, detail=f"Invalid sort column: {sort_by}")

    # Build query
    where_clause = ""
    params = {}

    if tenant_filter and "tenant_id" in col_names:
        params["tenant_filter"] = tenant_filter
        where_clause = 'WHERE "tenant_id" = :tenant_filter'

    if search:
        # Search across all text-like columns
        text_cols = [c["name"] for c in columns if any(
            t in str(c["type"]).upper()
            for t in ("CHAR", "TEXT", "VARCHAR")
        )]
        if not text_cols:
            text_cols = col_names[:3]  # fallback: search first 3 columns

        conditions = []
        for i, col in enumerate(text_cols):
            param_name = f"search_{i}"
            conditions.append(f'"{col}"::text ILIKE :{param_name}')
            params[param_name] = f"%{search}%"
        search_clause = f"({' OR '.join(conditions)})"
        if where_clause:
            where_clause = f"{where_clause} AND {search_clause}"
        else:
            where_clause = f"WHERE {search_clause}"

    # Sort
    order_clause = ""
    if sort_by:
        direction = "DESC" if sort_dir == "desc" else "ASC"
        order_clause = f'ORDER BY "{sort_by}" {direction} NULLS LAST'
    else:
        # Default: order by primary key or first column
        pk = inspector.get_pk_constraint(table_name, "public")
        pk_col = pk["constrained_columns"][0] if pk and pk.get("constrained_columns") else col_names[0]
        order_clause = f'ORDER BY "{pk_col}" DESC'

    # Count total (for pagination)
    count_sql = f'SELECT COUNT(*) FROM "{table_name}" {where_clause}'
    total = db.execute(text(count_sql), params).scalar() or 0

    # Fetch page
    offset = (page - 1) * page_size
    data_sql = f'SELECT * FROM "{table_name}" {where_clause} {order_clause} LIMIT :limit OFFSET :offset'
    params["limit"] = page_size
    params["offset"] = offset

    rows = db.execute(text(data_sql), params).mappings().all()

    # Serialize rows (handle non-JSON types like datetime, bytes, etc.)
    serialized = []
    for row in rows:
        row_dict = {}
        for k, v in row.items():
            if v is None:
                row_dict[k] = None
            elif isinstance(v, (str, int, float, bool)):
                row_dict[k] = v
            elif isinstance(v, dict):
                row_dict[k] = v
            elif isinstance(v, list):
                row_dict[k] = v
            else:
                row_dict[k] = str(v)
        serialized.append(row_dict)

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
        "columns": col_names,
        "rows": serialized,
    }


# ── Update a row by PK ─────────────────────────────────────────────

@router.put("/tables/{table_name}/rows/{row_id}")
async def update_row(
    request: Request,
    table_name: str,
    row_id: int,
    data: Dict[str, Any] = Body(..., embed=True),
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    """Update a row identified by its primary key."""
    inspector = sa_inspect(engine)
    _validate_table(inspector, table_name)

    pk_col = _get_pk_column(inspector, table_name)
    columns = inspector.get_columns(table_name, schema="public")
    valid_cols = {c["name"] for c in columns}

    # Filter data to only valid columns
    updates = {k: v for k, v in data.items() if k in valid_cols and k != pk_col}
    if not updates:
        raise HTTPException(status_code=400, detail="No valid columns to update")

    # Build SET clause with parameterized values
    set_parts = []
    params = {"pk_value": row_id}
    for i, (col, val) in enumerate(updates.items()):
        param_name = f"val_{i}"
        set_parts.append(f'"{col}" = :{param_name}')
        params[param_name] = val

    set_clause = ", ".join(set_parts)
    sql = f'UPDATE "{table_name}" SET {set_clause} WHERE "{pk_col}" = :pk_value RETURNING *'

    try:
        result = db.execute(text(sql), params)
        row = result.mappings().first()
        if not row:
            raise HTTPException(status_code=404, detail=f"Row with {pk_col}={row_id} not found")
        db.commit()
        return {"success": True, "row": {k: _serialize_value(v) for k, v in row.items()}}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Update failed: {str(e)}")


# ── Delete a row by PK ──────────────────────────────────────────────

@router.delete("/tables/{table_name}/rows/{row_id}")
async def delete_row(
    request: Request,
    table_name: str,
    row_id: int,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    """Delete a row identified by its primary key."""
    inspector = sa_inspect(engine)
    _validate_table(inspector, table_name)

    pk_col = _get_pk_column(inspector, table_name)
    sql = f'DELETE FROM "{table_name}" WHERE "{pk_col}" = :pk_value RETURNING "{pk_col}"'

    try:
        result = db.execute(text(sql), {"pk_value": row_id})
        deleted = result.first()
        if not deleted:
            raise HTTPException(status_code=404, detail=f"Row with {pk_col}={row_id} not found")
        db.commit()
        return {"success": True, "deleted_id": row_id}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Delete failed: {str(e)}")


# ── Insert a new row ────────────────────────────────────────────────

class RowInsert(BaseModel):
    data: Dict[str, Any]


@router.post("/tables/{table_name}/rows", status_code=201)
async def insert_row(
    request: Request,
    table_name: str,
    body: RowInsert,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    """Insert a new row into the table."""
    inspector = sa_inspect(engine)
    _validate_table(inspector, table_name)

    from datetime import datetime, timezone as tz

    columns = inspector.get_columns(table_name, schema="public")
    valid_cols = {c["name"] for c in columns}

    # Filter to valid columns
    insert_data = {k: v for k, v in body.data.items() if k in valid_cols}

    # Auto-fill missing datetime columns (columns with "time", "date", "at" in name)
    for col in columns:
        cname = col["name"]
        if cname not in insert_data:
            col_type_str = str(col["type"]).upper()
            # Auto-fill datetime columns
            if ("timestamp" in col_type_str.lower() or "datetime" in col_type_str.lower()):
                insert_data[cname] = datetime.now(tz.utc)
            # Auto-fill boolean columns with False as default
            elif "bool" in col_type_str.lower() and col.get("default") is None:
                insert_data[cname] = False

    if not insert_data:
        raise HTTPException(status_code=400, detail="No valid columns provided")

    col_names = list(insert_data.keys())
    placeholders = list(insert_data.keys())
    params = {k: v for k, v in insert_data.items()}

    cols_str = ", ".join(f'"{c}"' for c in col_names)
    vals_str = ", ".join(f":{c}" for c in col_names)

    sql = f'INSERT INTO "{table_name}" ({cols_str}) VALUES ({vals_str}) RETURNING *'

    try:
        result = db.execute(text(sql), params)
        row = result.mappings().first()
        db.commit()
        return {"success": True, "row": {k: _serialize_value(v) for k, v in row.items()}}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Insert failed: {str(e)}")


# ── Delete (drop) a table ─────────────────────────────────────────

# Tables that should NEVER be droppable through the UI
PROTECTED_TABLES = {"users", "connection_logs", "suricata_alerts",
                    "assets", "alerts", "ia_reports", "access_logs", "action_logs",
                    "system_config", "network_sensors", "devices",
                    "tenants", "tenant_users", "network_devices",
                    "rules", "rule_match_events", "pipeline_events",
                    "cases", "case_alert_links", "timeline_events", "hunts",
                    "playbooks", "playbook_runs", "playbook_step_results",
                    "threat_intel_cache"}


@router.delete("/tables/{table_name}")
async def drop_table(
    request: Request,
    table_name: str,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    """Drop a table. Protected system tables cannot be dropped."""
    inspector = sa_inspect(engine)
    valid_tables = set(inspector.get_table_names(schema="public"))
    if table_name not in valid_tables:
        raise HTTPException(status_code=404, detail=f"Table '{table_name}' not found")
    if table_name in PROTECTED_TABLES:
        raise HTTPException(
            status_code=403,
            detail=f"Table '{table_name}' is a system table and cannot be dropped",
        )

    try:
        # Count rows before dropping (for info)
        count = db.execute(text(f'SELECT COUNT(*) FROM "{table_name}"')).scalar() or 0
        db.execute(text(f'DROP TABLE IF EXISTS "{table_name}" CASCADE'))
        db.commit()
        return {"success": True, "dropped": table_name, "rows_lost": count}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Drop failed: {str(e)}")


# ── Create a new table ────────────────────────────────────────────

# Allowed PostgreSQL types for user-created tables
ALLOWED_TYPES = {
    "integer", "bigint", "smallint",
    "real", "double precision", "numeric",
    "boolean",
    "character varying", "varchar", "text", "char",
    "date", "time", "timestamp", "timestamp without time zone", "timestamp with time zone",
    "json", "jsonb",
    "uuid", "bytea",
}


class ColumnDef(BaseModel):
    name: str
    type: str  # e.g. "integer", "varchar(255)", "text", "boolean"
    nullable: bool = True
    primary_key: bool = False
    default: Optional[str] = None  # raw SQL default e.g. "now()", "gen_random_uuid()"


class CreateTableRequest(BaseModel):
    table_name: str
    columns: List[ColumnDef]


def _validate_identifier(name: str) -> str:
    """Validate a table or column name is a safe SQL identifier."""
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
        raise HTTPException(status_code=400, detail=f"Invalid identifier: '{name}'")
    return name


@router.post("/tables", status_code=201)
async def create_table(
    request: Request,
    body: CreateTableRequest,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    """Create a new table with specified columns."""
    inspector = sa_inspect(engine)

    table_name = _validate_identifier(body.table_name.strip())

    # Check table doesn't already exist
    existing = set(inspector.get_table_names(schema="public"))
    if table_name in existing:
        raise HTTPException(status_code=409, detail=f"Table '{table_name}' already exists")

    if not body.columns or len(body.columns) < 1:
        raise HTTPException(status_code=400, detail="At least one column is required")

    # Validate column names
    for col in body.columns:
        _validate_identifier(col.name.strip())

    # Build CREATE TABLE SQL
    col_defs = []
    pk_cols = []
    for col in body.columns:
        col_name = col.name.strip()
        # Normalize type: "varchar(255)" → "VARCHAR(255)", "text" → "TEXT", etc.
        col_type = col.type.strip().upper()

        parts = [f'"{col_name}" {col_type}']

        if not col.nullable:
            parts.append("NOT NULL")

        if col.primary_key:
            pk_cols.append(f'"{col_name}"')
            parts.append("PRIMARY KEY")
        elif col.default is not None:
            # Validate default is a simple safe SQL expression
            parts.append(f"DEFAULT {col.default}")

        col_defs.append("    " + " ".join(parts))

    # Add composite PK if multiple PKs
    if len(pk_cols) > 1:
        col_defs.append(f"    PRIMARY KEY ({', '.join(pk_cols)})")

    create_sql = f'CREATE TABLE "{table_name}" (\n' + ",\n".join(col_defs) + "\n)"

    try:
        db.execute(text(create_sql))
        db.commit()
        return {
            "success": True,
            "table": table_name,
            "columns": len(body.columns),
            "sql": create_sql,
        }
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Create table failed: {str(e)}")
