import pytest

from common.interfaces.message_bus import MessageBus
from common.interfaces.document_store import DocumentStore
from common.interfaces.secret_provider import SecretProvider
from common.interfaces.llm_client import LLMClient, LLMResponse
from common.interfaces.telemetry_client import TelemetryClient, TableSchema


@pytest.mark.parametrize("cls", [MessageBus, DocumentStore, SecretProvider, LLMClient, TelemetryClient])
def test_interfaces_cannot_be_instantiated(cls):
    with pytest.raises(TypeError):
        cls()


def test_minimal_subclass_satisfies_message_bus():
    class FakeBus(MessageBus):
        def publish(self, topic, payload):
            return f"{topic}:1"

    assert FakeBus().publish("alerts", {"a": 1}) == "alerts:1"


def test_minimal_subclass_satisfies_secret_provider():
    class FakeSecrets(SecretProvider):
        def get_secret(self, name):
            return None

    assert FakeSecrets().get_secret("missing") is None


def test_llm_response_dataclass_shape():
    resp = LLMResponse(text="hi", function_call=None, input_tokens=10, output_tokens=2, model="m")
    assert resp.input_tokens == 10
    assert resp.function_call is None


def test_table_schema_defaults():
    schema = TableSchema(name="auth_events", columns=[{"name": "ts", "type": "timestamp"}])
    assert schema.requires_partition_filter is False
