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


def test_minimal_subclass_satisfies_document_store():
    class FakeStore(DocumentStore):
        def save_alert(self, alert):
            pass

        def get_alert(self, alert_id):
            return None

        def vector_search(self, embedding, limit, threshold, lookback_seconds):
            return []

        def find_open_ticket_by_host_code(self, hostname, code):
            return None

        def save_grant(self, grant):
            pass

        def find_active_grants(self, user=None, resource=None):
            return []

    assert FakeStore().get_alert("x") is None


def test_minimal_subclass_satisfies_llm_client():
    class FakeClient(LLMClient):
        def generate(self, system, messages, tools=None):
            return LLMResponse(text="", function_call=None, input_tokens=0, output_tokens=0, model="m")

    assert FakeClient().generate("sys", []).text == ""


def test_minimal_subclass_satisfies_telemetry_client():
    class FakeTC(TelemetryClient):
        def list_tables(self, substr):
            return []

        def describe_table(self, table):
            return TableSchema(name=table)

        def query(self, sql):
            return []

    assert FakeTC().list_tables("") == []


def test_llm_response_dataclass_shape():
    resp = LLMResponse(text="hi", function_call=None, input_tokens=10, output_tokens=2, model="m")
    assert resp.input_tokens == 10
    assert resp.function_call is None


def test_table_schema_defaults():
    schema = TableSchema(name="auth_events", columns=[{"name": "ts", "type": "timestamp"}])
    assert schema.requires_partition_filter is False
