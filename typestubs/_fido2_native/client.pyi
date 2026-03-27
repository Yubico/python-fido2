from typing import Any, Callable, Sequence

class ClientDataCollector:
    origin: str
    def __init__(
        self,
        origin: str,
        verify: Callable[[str, str], bool] | None = None,
    ) -> None: ...
    def get_rp_id(self, rp_id: str | None = None) -> str: ...
    def verify_rp_id_py(self, rp_id: str) -> None: ...
    def collect_client_data(
        self,
        type_: str,
        challenge: bytes,
        rp_id: str | None = None,
    ) -> tuple[bytes, str]: ...

class NativeFido2Client:
    info: dict[str, Any]
    def __init__(
        self,
        device: Any,
        user_interaction: Any,
        on_keepalive: Callable[[int], None],
        extensions: Sequence[Any] | None = None,
    ) -> None: ...
    def selection(self, event: Any | None = None) -> None: ...
    def do_make_credential(
        self,
        options_json: str,
        client_data_hash: bytes,
        rp_id: str,
        event: Any | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]: ...
    def do_get_assertion(
        self,
        options_json: str,
        client_data_hash: bytes,
        rp_id: str,
        event: Any | None = None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]: ...
