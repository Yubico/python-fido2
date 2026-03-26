from typing import Any, Callable

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

class NativeCtap2ClientBackend:
    def __init__(self, device: Any, strict_cbor: bool, max_msg_size: int) -> None: ...
    def filter_creds(
        self,
        rp_id: str,
        cred_list: list[Any],
        pin_version: int | None,
        pin_token: bytes | None,
        event: Any | None = None,
        on_keepalive: Callable[[int], None] | None = None,
    ) -> dict[str, Any] | None: ...
    def get_auth_params(
        self,
        rp_id: str,
        user_verification: str | None,
        permissions: int,
        pin_version: int | None,
        allow_uv: bool,
        event: Any | None = None,
        on_keepalive: Callable[[int], None] | None = None,
        user_interaction: Any | None = None,
    ) -> tuple[bytes | None, bool]: ...
