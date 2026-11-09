"""Windows client tests with the native WebAuthn call replaced by a stub."""

import ctypes
import importlib.util
import sys
from pathlib import Path
from unittest import mock

import pytest

from fido2.client import DefaultClientDataCollector


@pytest.fixture
def windows():
    dll = mock.MagicMock()
    dll.WebAuthNGetApiVersionNumber.return_value = 3
    # Load the real client and ctypes structures without requiring Windows DLLs.
    with (
        mock.patch.object(ctypes, "WinDLL", return_value=dll, create=True),
        mock.patch.object(ctypes, "HRESULT", ctypes.c_long, create=True),
        mock.patch.dict(sys.modules),
    ):
        sys.modules.pop("fido2.client.win_api", None)
        spec = importlib.util.spec_from_file_location(
            "fido2.client._test_windows",
            Path(__file__).parents[1] / "fido2/client/windows.py",
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        yield module


@pytest.mark.parametrize(
    "extensions,status,expected",
    [
        ({"appid": "https://example.com"}, 2, {"appid": False}),
        (None, 2, {}),
        ({"largeBlob": {"read": True}}, 2, {"largeBlob": {"blob": "YmxvYg"}}),
        ({"largeBlob": {"write": b"blob"}}, 1, {"largeBlob": {"written": True}}),
        ({"largeBlob": {"write": b"blob"}}, 2, {"largeBlob": {"written": False}}),
        ({"largeBlob": {"read": True}}, 0, {}),
    ],
)
def test_get_assertion_large_blob(windows, extensions, status, expected):
    assertion = windows.WebAuthNAssertion()
    assertion.dwVersion = 2
    assertion.dwCredLargeBlobStatus = status
    assertion.auth_data = b"\0" * 37
    assertion.signature = b"signature"
    assertion.Credential.pwszCredentialType = "public-key"
    assertion.Credential.id = b"credential-id"
    assertion.cred_large_blob = b"blob"

    def get_assertion(handle, rp_id, client_data, options, output):
        ctypes.cast(output, ctypes.POINTER(ctypes.POINTER(type(assertion))))[0] = (
            ctypes.pointer(assertion)
        )

    windows.WEBAUTHN.WebAuthNAuthenticatorGetAssertion.side_effect = get_assertion
    client = windows.WindowsClient(
        DefaultClientDataCollector("https://example.com"), handle=1
    )
    result = client.get_assertion(
        {"challenge": b"challenge", "rpId": "example.com", "extensions": extensions}
    ).get_response(0)

    assert result.raw_id == b"credential-id"
    assert dict(result.client_extension_results) == expected
