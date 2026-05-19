from app.models import RegistryEvent
from app.services.crypto import utc_now
from app.services.event_plane import event_message, event_subject, stream_config


def test_event_subject_normalizes_type() -> None:
    assert event_subject("identity_registered", prefix="tovbase.id.registry") == (
        "tovbase.id.registry.identity-registered"
    )


def test_event_message_is_json_safe() -> None:
    event = RegistryEvent(
        event_id="evt_1",
        event_type="identity_registered",
        aggregate_id="hash",
        aggregate_type="identity_hash",
        sequence_number=1,
        occurred_at=utc_now(),
        payload={"registered_at": utc_now()},
        payload_hash="00" * 32,
        previous_event_hash=None,
        event_hash="11" * 32,
    )
    message = event_message(event)

    assert message["event_id"] == "evt_1"
    assert message["occurred_at"].endswith("Z")
    assert message["payload"]["registered_at"].endswith("Z")


def test_stream_config_uses_registry_subject_prefix() -> None:
    config = stream_config()

    assert config["name"]
    assert config["subjects"][0].endswith(".>")
