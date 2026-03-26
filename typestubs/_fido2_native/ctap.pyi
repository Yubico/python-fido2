from typing import Any, Callable, Mapping

class NativeCtap1:
    def __init__(self, device: Any) -> None: ...
    def send_apdu(self, cla: int, ins: int, p1: int, p2: int, data: bytes) -> bytes: ...
    def get_version(self) -> str: ...
    def register(
        self, client_param: bytes, app_param: bytes
    ) -> tuple[bytes, bytes, bytes, bytes]: ...
    def authenticate(
        self,
        client_param: bytes,
        app_param: bytes,
        key_handle: bytes,
        check_only: bool = False,
    ) -> tuple[int, int, bytes]: ...

class NativeCtap2:
    info: dict[str, Any]
    max_msg_size: int
    def __init__(
        self, device: Any, strict_cbor: bool = True, max_msg_size: int = 1024
    ) -> None: ...
    def send_cbor(
        self,
        cmd: int,
        data: Mapping[int, Any] | None = None,
        event: Any | None = None,
        on_keepalive: Callable[[int], None] | None = None,
    ) -> Mapping[int, Any]: ...
    def refresh_info(self) -> dict[str, Any]: ...
    def make_credential(
        self,
        client_data_hash: bytes,
        rp: Mapping[str, Any],
        user: Mapping[str, Any],
        key_params: list[Mapping[str, Any]],
        exclude_list: list[Mapping[str, Any]] | None = None,
        extensions: Mapping[str, Any] | None = None,
        options: Mapping[str, Any] | None = None,
        pin_uv_param: bytes | None = None,
        pin_uv_protocol: int | None = None,
        enterprise_attestation: int | None = None,
        event: Any | None = None,
        on_keepalive: Callable[[int], None] | None = None,
    ) -> dict[str, Any]: ...
    def get_assertion(
        self,
        rp_id: str,
        client_data_hash: bytes,
        allow_list: list[Mapping[str, Any]] | None = None,
        extensions: Mapping[str, Any] | None = None,
        options: Mapping[str, Any] | None = None,
        pin_uv_param: bytes | None = None,
        pin_uv_protocol: int | None = None,
        event: Any | None = None,
        on_keepalive: Callable[[int], None] | None = None,
    ) -> dict[str, Any]: ...
    def get_next_assertion(self) -> dict[str, Any]: ...
    def get_assertions(
        self,
        rp_id: str,
        client_data_hash: bytes,
        allow_list: list[Mapping[str, Any]] | None = None,
        extensions: Mapping[str, Any] | None = None,
        options: Mapping[str, Any] | None = None,
        pin_uv_param: bytes | None = None,
        pin_uv_protocol: int | None = None,
        event: Any | None = None,
        on_keepalive: Callable[[int], None] | None = None,
    ) -> list[dict[str, Any]]: ...
    def client_pin(
        self,
        pin_uv_protocol: int,
        sub_cmd: int,
        key_agreement: Mapping[int, Any] | None = None,
        pin_uv_param: bytes | None = None,
        new_pin_enc: bytes | None = None,
        pin_hash_enc: bytes | None = None,
        permissions: int | None = None,
        permissions_rpid: str | None = None,
        event: Any | None = None,
        on_keepalive: Callable[[int], None] | None = None,
    ) -> Mapping[int, Any]: ...
    def selection(
        self,
        event: Any | None = None,
        on_keepalive: Callable[[int], None] | None = None,
    ) -> None: ...
    def reset(
        self,
        event: Any | None = None,
        on_keepalive: Callable[[int], None] | None = None,
    ) -> None: ...
    def credential_mgmt(
        self,
        cmd_byte: int,
        sub_cmd: int,
        sub_cmd_params: Mapping[int, Any] | None = None,
        pin_uv_protocol: int | None = None,
        pin_uv_param: bytes | None = None,
        event: Any | None = None,
        on_keepalive: Callable[[int], None] | None = None,
    ) -> Mapping[int, Any]: ...
    def bio_enrollment(
        self,
        cmd_byte: int,
        modality: int | None = None,
        sub_cmd: int | None = None,
        sub_cmd_params: Mapping[int, Any] | None = None,
        pin_uv_protocol: int | None = None,
        pin_uv_param: bytes | None = None,
        get_modality: bool | None = None,
        event: Any | None = None,
        on_keepalive: Callable[[int], None] | None = None,
    ) -> Mapping[int, Any]: ...
    def large_blobs(
        self,
        offset: int,
        get: int | None = None,
        set: bytes | None = None,
        length: int | None = None,
        pin_uv_param: bytes | None = None,
        pin_uv_protocol: int | None = None,
        event: Any | None = None,
        on_keepalive: Callable[[int], None] | None = None,
    ) -> Mapping[int, Any]: ...
    def config(
        self,
        sub_cmd: int,
        sub_cmd_params: Mapping[int, Any] | None = None,
        pin_uv_protocol: int | None = None,
        pin_uv_param: bytes | None = None,
        event: Any | None = None,
        on_keepalive: Callable[[int], None] | None = None,
    ) -> Mapping[int, Any]: ...
