from typing import Callable

def verify_rp_id(rp_id: str, origin: str) -> bool: ...
def verify_registration(
    client_data: bytes,
    attestation_object: bytes,
    challenge: bytes,
    rp_id_hash: bytes,
    user_verification_required: bool,
) -> None: ...
def verify_authentication(
    client_data: bytes,
    auth_data: bytes,
    challenge: bytes,
    rp_id_hash: bytes,
    user_verification_required: bool,
) -> None: ...

class Fido2Server:
    rp_id_hash: bytes
    allowed_algorithms: list[int]
    def __init__(
        self,
        rp_id: str,
        rp_name: str,
        attestation: str | None = None,
        verify_origin: Callable[[str], bool] | None = None,
        verify_attestation: Callable[[bytes, bytes], None] | None = None,
    ) -> None: ...
    def check_origin_py(self, origin: str) -> bool: ...
    def generate_challenge(self, challenge: bytes | None = None) -> bytes: ...
    def register_complete(
        self,
        client_data: bytes,
        attestation_object: bytes,
        challenge: bytes,
        user_verification_required: bool,
    ) -> None: ...
    def authenticate_complete(
        self,
        client_data: bytes,
        auth_data: bytes,
        challenge: bytes,
        user_verification_required: bool,
        credentials: list[tuple[bytes, bytes]],
        credential_id: bytes,
        signature: bytes,
    ) -> int: ...
