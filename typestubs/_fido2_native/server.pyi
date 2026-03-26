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
