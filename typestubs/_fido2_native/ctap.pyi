from typing import Any, Callable, Mapping

class NativeCtap1:
    def __init__(self, device: Any) -> None: ...
    def send_apdu(self, cla: int, ins: int, p1: int, p2: int, data: bytes) -> bytes: ...
    def get_version(self) -> str: ...
    def register(self, client_param: bytes, app_param: bytes) -> bytes: ...
    def authenticate(
        self,
        client_param: bytes,
        app_param: bytes,
        key_handle: bytes,
        check_only: bool = False,
    ) -> bytes: ...

class NativeCtap2:
    info: dict[str, Any]
    max_msg_size: int
    device: Any
    strict_cbor: bool
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
        sub_cmd: int,
        sub_cmd_params: Mapping[int, Any] | None = None,
        pin_uv_protocol: int | None = None,
        pin_uv_param: bytes | None = None,
        event: Any | None = None,
        on_keepalive: Callable[[int], None] | None = None,
    ) -> Mapping[int, Any]: ...
    def bio_enrollment(
        self,
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
    def create_credential_management(
        self,
        protocol_version: int,
        pin_uv_token: bytes,
    ) -> NativeCredentialManagement: ...
    def create_bio_enrollment(
        self,
        protocol_version: int,
        pin_uv_token: bytes,
        modality: int,
    ) -> NativeFPBioEnrollment: ...

class NativeClientPin:
    def __init__(
        self,
        device: Any,
        strict_cbor: bool,
        max_msg_size: int,
        protocol_version: int,
    ) -> None: ...
    def get_pin_token(
        self,
        pin: str,
        permissions: int | None = None,
        permissions_rpid: str | None = None,
    ) -> bytes: ...
    def get_uv_token(
        self,
        permissions: int | None = None,
        permissions_rpid: str | None = None,
        event: Any | None = None,
        on_keepalive: Callable[[int], None] | None = None,
    ) -> bytes: ...
    def get_pin_retries(self) -> tuple[int, int | None]: ...
    def get_uv_retries(self) -> int: ...
    def set_pin(self, pin: str) -> None: ...
    def change_pin(self, old_pin: str, new_pin: str) -> None: ...
    def get_shared_secret(self) -> tuple[dict[int, Any], bytes]: ...

class NativeCredentialManagement:
    def get_metadata(self) -> Mapping[int, Any]: ...
    def enumerate_rps_begin(self) -> Mapping[int, Any]: ...
    def enumerate_rps_next(self) -> Mapping[int, Any]: ...
    def enumerate_rps(self) -> list[Mapping[int, Any]]: ...
    def enumerate_creds_begin(self, rp_id_hash: bytes) -> Mapping[int, Any]: ...
    def enumerate_creds_next(self) -> Mapping[int, Any]: ...
    def enumerate_creds(self, rp_id_hash: bytes) -> list[Mapping[int, Any]]: ...
    def delete_cred(self, cred_id: Any) -> None: ...
    def update_user_info(self, cred_id: Any, user: Any) -> None: ...

class NativeFPBioEnrollment:
    def get_fingerprint_sensor_info(
        self,
        event: Any | None = None,
        on_keepalive: Callable[[int], None] | None = None,
    ) -> Mapping[int, Any]: ...
    def enroll_begin(
        self,
        timeout: int | None = None,
        event: Any | None = None,
        on_keepalive: Callable[[int], None] | None = None,
    ) -> tuple[bytes, int, int]: ...
    def enroll_capture_next(
        self,
        template_id: bytes,
        timeout: int | None = None,
        event: Any | None = None,
        on_keepalive: Callable[[int], None] | None = None,
    ) -> tuple[int, int]: ...
    def enroll_cancel(self) -> None: ...
    def enumerate_enrollments(self) -> Mapping[int, Any]: ...
    def set_name(self, template_id: bytes, name: str) -> None: ...
    def remove_enrollment(self, template_id: bytes) -> None: ...

class NativeLargeBlobs:
    def __init__(
        self,
        device: Any,
        strict_cbor: bool,
        max_msg_size: int,
        max_fragment_length: int,
        protocol_version: int | None = None,
        pin_uv_token: bytes | None = None,
    ) -> None: ...
    def read_blob_array(self) -> list[Mapping[int, Any]]: ...
    def write_blob_array(self, blob_array: Any) -> None: ...
    def get_blob(self, large_blob_key: bytes) -> bytes | None: ...
    def put_blob(self, large_blob_key: bytes, data: bytes | None) -> None: ...
    def delete_blob(self, large_blob_key: bytes) -> None: ...

class NativeConfig:
    def __init__(
        self,
        device: Any,
        strict_cbor: bool,
        max_msg_size: int,
        protocol_version: int | None = None,
        pin_uv_token: bytes | None = None,
    ) -> None: ...
    def enable_enterprise_attestation(self) -> None: ...
    def toggle_always_uv(self) -> None: ...
    def set_min_pin_length(
        self,
        min_pin_length: int | None = None,
        rp_ids: list[str] | None = None,
        force_change_pin: bool = False,
    ) -> None: ...
