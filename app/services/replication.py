from __future__ import annotations

import re
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.config import settings

REPLICATED_TABLES = (
    "identity_hashes",
    "registry_events",
    "did_documents",
    "registration_receipts",
    "bank_attestations",
    "signed_actions",
    "action_attestations",
    "registry_anchors",
)

IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")


def validate_identifier(value: str, *, label: str = "identifier") -> str:
    if not IDENTIFIER_RE.fullmatch(value):
        raise ValueError(f"{label} must contain only letters, numbers, and underscores, and cannot start with a number")
    return value


def quote_identifier(value: str) -> str:
    return f'"{validate_identifier(value)}"'


def table_list_sql(tables: tuple[str, ...] = REPLICATED_TABLES) -> str:
    return ", ".join(quote_identifier(table) for table in tables)


def publication_sql(publication_name: str | None = None, *, tables: tuple[str, ...] = REPLICATED_TABLES) -> list[str]:
    publication_name = validate_identifier(
        publication_name or settings.registry_publication_name,
        label="publication_name",
    )
    table_names = table_list_sql(tables)
    create_publication = (
        "DO $$\n"
        "BEGIN\n"
        f"  IF NOT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = '{publication_name}') THEN\n"
        f"    EXECUTE 'CREATE PUBLICATION {quote_identifier(publication_name)} "
        f"FOR TABLE {table_names} WITH (publish = ''insert, update'')';\n"
        "  END IF;\n"
        "END;\n"
        "$$;"
    )
    set_tables = f"ALTER PUBLICATION {quote_identifier(publication_name)} SET TABLE {table_names};"
    return [create_publication, set_tables]


def subscription_sql(
    *,
    subscription_name: str,
    publication_name: str | None = None,
    publisher_host: str,
    publisher_port: int = 5432,
    publisher_db: str,
    publisher_user: str,
    slot_name: str | None = None,
    sslmode: str = "require",
) -> str:
    subscription_name = validate_identifier(subscription_name, label="subscription_name")
    publication_name = validate_identifier(
        publication_name or settings.registry_publication_name,
        label="publication_name",
    )
    if slot_name is not None:
        slot_name = validate_identifier(slot_name, label="slot_name")
    if publisher_port <= 0 or publisher_port > 65535:
        raise ValueError("publisher_port must be a valid TCP port")

    conninfo = (
        f"host={publisher_host} port={publisher_port} dbname={publisher_db} "
        f"user={publisher_user} password=<publisher_replication_password> sslmode={sslmode}"
    )
    slot_clause = f", slot_name = '{slot_name}'" if slot_name else ""
    return (
        f"CREATE SUBSCRIPTION {quote_identifier(subscription_name)}\n"
        f"CONNECTION '{conninfo}'\n"
        f"PUBLICATION {quote_identifier(publication_name)}\n"
        f"WITH (create_slot = true, enabled = true, copy_data = true{slot_clause});"
    )


def configure_publication(db: Session, publication_name: str | None = None) -> dict[str, Any]:
    if db.bind is None or db.bind.dialect.name != "postgresql":
        raise RuntimeError("logical replication publication setup requires a PostgreSQL database")

    statements = publication_sql(publication_name)
    for statement in statements:
        db.execute(text(statement))
    db.commit()
    return replication_status(db, publication_name=publication_name)


def _safe_scalar(db: Session, statement: str, params: dict[str, Any] | None = None) -> Any:
    try:
        return db.execute(text(statement), params or {}).scalar_one_or_none()
    except SQLAlchemyError:
        return None


def _safe_rows(db: Session, statement: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    try:
        return [dict(row._mapping) for row in db.execute(text(statement), params or {}).all()]
    except SQLAlchemyError:
        return []


def replication_status(db: Session, publication_name: str | None = None) -> dict[str, Any]:
    publication_name = publication_name or settings.registry_publication_name
    if db.bind is None:
        return {
            "mode": "unknown",
            "publication": publication_name,
            "dialect": "unknown",
            "expected_tables": list(REPLICATED_TABLES),
        }

    dialect = db.bind.dialect.name
    status: dict[str, Any] = {
        "mode": "not_configured" if dialect != "postgresql" else "postgresql",
        "publication": publication_name,
        "dialect": dialect,
        "expected_tables": list(REPLICATED_TABLES),
    }
    if dialect != "postgresql":
        return status

    publication_exists = bool(
        _safe_scalar(
            db,
            "SELECT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = :publication_name)",
            {"publication_name": publication_name},
        )
    )
    publication_tables = _safe_rows(
        db,
        """
        SELECT tablename
        FROM pg_publication_tables
        WHERE pubname = :publication_name
        ORDER BY tablename
        """,
        {"publication_name": publication_name},
    )
    table_names = {row["tablename"] for row in publication_tables}
    missing_tables = [table for table in REPLICATED_TABLES if table not in table_names]
    in_recovery = bool(_safe_scalar(db, "SELECT pg_is_in_recovery()"))

    status.update(
        {
            "mode": "mirror" if in_recovery else "primary",
            "publication_exists": publication_exists,
            "publication_tables": sorted(table_names),
            "missing_tables": missing_tables,
            "current_lsn": _safe_scalar(db, "SELECT pg_current_wal_lsn()::text") if not in_recovery else None,
            "replay_lsn": _safe_scalar(db, "SELECT pg_last_wal_replay_lsn()::text") if in_recovery else None,
            "replay_lag_seconds": _safe_scalar(
                db,
                """
                SELECT EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()))
                WHERE pg_last_xact_replay_timestamp() IS NOT NULL
                """,
            )
            if in_recovery
            else None,
            "replication_clients": _safe_rows(
                db,
                """
                SELECT application_name,
                       state,
                       sync_state,
                       sent_lsn::text,
                       write_lsn::text,
                       flush_lsn::text,
                       replay_lsn::text,
                       pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn) AS replay_lag_bytes
                FROM pg_stat_replication
                ORDER BY application_name
                """,
            )
            if not in_recovery
            else [],
        }
    )
    return status
