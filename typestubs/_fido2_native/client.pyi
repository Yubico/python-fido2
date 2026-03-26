from typing import Callable

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
