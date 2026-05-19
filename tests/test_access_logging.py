import json
import logging


def test_access_log_uses_route_template_and_request_id(client, caplog) -> None:
    hash_id = "a" * 64
    with caplog.at_level(logging.INFO, logger="tovbase_id.access"):
        response = client.get(
            f"/v1/did/hash/{hash_id}?nin=12345678901",
            headers={"X-Request-ID": "req_test_123"},
        )

    assert response.status_code == 404
    assert response.headers["x-request-id"] == "req_test_123"

    records = [record for record in caplog.records if record.name == "tovbase_id.access"]
    assert records
    message = records[-1].getMessage()
    payload = json.loads(message)
    assert payload["event"] == "http_request"
    assert payload["request_id"] == "req_test_123"
    assert payload["method"] == "GET"
    assert payload["path_template"] == "/v1/did/hash/{hash_id}"
    assert payload["status_code"] == 404
    assert payload["failed"] is False
    assert hash_id not in message
    assert "nin" not in message
    assert "12345678901" not in message
