import pytest

from app.services.replication import (
    REPLICATED_TABLES,
    publication_sql,
    subscription_sql,
    validate_identifier,
)


def test_publication_sql_includes_all_registry_tables() -> None:
    statements = publication_sql("did_registry_publication")
    rendered = "\n".join(statements)

    assert "CREATE PUBLICATION" in rendered
    assert "ALTER PUBLICATION" in rendered
    for table in REPLICATED_TABLES:
        assert f'"{table}"' in rendered
    assert "WITH (publish = ''insert, update'')" in rendered


def test_identifier_validation_rejects_unsafe_values() -> None:
    with pytest.raises(ValueError):
        validate_identifier("bad-name;drop")
    with pytest.raises(ValueError):
        validate_identifier("1starts_with_number")


def test_subscription_sql_uses_safe_identifiers_and_password_placeholder() -> None:
    rendered = subscription_sql(
        subscription_name="bank_a_did_registry_sub",
        publication_name="did_registry_publication",
        publisher_host="primary.internal",
        publisher_db="tovbase_id",
        publisher_user="repl_tovbase_id",
        slot_name="bank_a_did_registry_slot",
    )

    assert 'CREATE SUBSCRIPTION "bank_a_did_registry_sub"' in rendered
    assert 'PUBLICATION "did_registry_publication"' in rendered
    assert "password=<publisher_replication_password>" in rendered
    assert "slot_name = 'bank_a_did_registry_slot'" in rendered


def test_replication_status_for_sqlite_is_not_configured(client) -> None:
    response = client.get("/v1/did/health")
    body = response.json()

    assert response.status_code == 200
    assert body["replication"]["mode"] == "not_configured"
    assert body["replication"]["dialect"] == "sqlite"
    assert body["replication"]["expected_tables"] == list(REPLICATED_TABLES)
