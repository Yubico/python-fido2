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
    enterprise_rpid_list: list[str] | None
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

class NativeExtension:
    @staticmethod
    def hmac_secret(allow_hmac_secret: bool) -> NativeExtension: ...
    @staticmethod
    def large_blob() -> NativeExtension: ...
    @staticmethod
    def cred_blob() -> NativeExtension: ...
    @staticmethod
    def cred_protect() -> NativeExtension: ...
    @staticmethod
    def min_pin_length() -> NativeExtension: ...
    @staticmethod
    def cred_props() -> NativeExtension: ...
    def is_supported(self, ctap: Any) -> bool: ...
    def make_credential(
        self,
        ctap: Any,
        options: Any,
        pin_protocol: Any,
    ) -> NativeRegistrationProcessor | None: ...
    def get_assertion(
        self,
        ctap: Any,
        options: Any,
        pin_protocol: Any,
    ) -> NativeAuthenticationProcessor | None: ...

class NativeRegistrationProcessor:
    permissions: int
    def prepare_inputs(self, pin_token: bytes | None) -> dict[str, Any] | None: ...
    def prepare_outputs(
        self, response: Any, pin_token: bytes | None
    ) -> dict[str, Any] | None: ...

class NativeAuthenticationProcessor:
    permissions: int
    def prepare_inputs(
        self, selected: Any, pin_token: bytes | None
    ) -> dict[str, Any] | None: ...
    def prepare_outputs(
        self, response: Any, pin_token: bytes | None
    ) -> dict[str, Any] | None: ...
