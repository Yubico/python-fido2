import os

import pytest

from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2.blob import LargeBlobs
from fido2.ctap2.pin import ClientPin
from fido2.server import Fido2Server
from fido2.utils import websafe_decode, websafe_encode

from . import TEST_PIN


@pytest.fixture(autouse=True, scope="module")
def preconditions(dev_manager):
    if not LargeBlobs.is_supported(dev_manager.info):
        pytest.skip("LargeBlobs not supported by authenticator")


def get_lb(ctap2, pin_protocol, permissions=ClientPin.PERMISSION.LARGE_BLOB_WRITE):
    token = ClientPin(ctap2, pin_protocol).get_pin_token(TEST_PIN, permissions)
    return LargeBlobs(ctap2, pin_protocol, token)


def test_read_write(ctap2, pin_protocol):
    lb = get_lb(ctap2, pin_protocol)
    assert len(lb.read_blob_array()) == 0

    key1 = os.urandom(32)
    data1 = b"test data"
    key2 = os.urandom(32)
    data2 = b"some other data"

    assert lb.get_blob(key1) is None
    lb.put_blob(key1, data1)
    assert lb.get_blob(key1) == data1
    assert len(lb.read_blob_array()) == 1

    lb.put_blob(key2, data2)
    assert lb.get_blob(key1) == data1
    assert lb.get_blob(key2) == data2
    assert len(lb.read_blob_array()) == 2

    lb.delete_blob(key1)
    assert lb.get_blob(key1) is None
    assert lb.get_blob(key2) == data2
    assert len(lb.read_blob_array()) == 1

    lb.delete_blob(key2)
    assert lb.get_blob(key2) is None
    assert len(lb.read_blob_array()) == 0


def test_size_bounds(ctap2, pin_protocol):
    lb = get_lb(ctap2, pin_protocol)
    assert len(lb.read_blob_array()) == 0

    # The max storage is the CBOR-encoded array, minus a 16 byte checksum
    max_size = ctap2.info.max_large_blob - 16

    # Create data which when cbor-encoded is exactly max_size bytes
    array = [{1: os.urandom(max_size - 8)}]
    array.extend([0] * (max_size - len(cbor.encode(array))))

    lb.write_blob_array(array)

    # Ensure writing larger data fails:
    array.append(1)
    with pytest.raises(CtapError, match="LARGE_BLOB_STORAGE_FULL"):
        lb.write_blob_array(array)

    # Clear the data
    lb.write_blob_array([])


def test_missing_permissions(ctap2, pin_protocol):
    key = os.urandom(32)
    data = b"test data"

    # Try write without PIN token
    lb = LargeBlobs(ctap2, pin_protocol)
    blobs = lb.read_blob_array()
    assert len(blobs) == 0

    with pytest.raises(CtapError, match="PUAT_REQUIRED"):
        lb.put_blob(key, data)

    # Try with wrong permissions
    lb = get_lb(ctap2, pin_protocol, ClientPin.PERMISSION.CREDENTIAL_MGMT)
    with pytest.raises(CtapError, match="PIN_AUTH_INVALID"):
        lb.put_blob(key, data)


def test_large_blob_key(client, ctap2, pin_protocol, clear_creds):
    rp = {"id": "example.com", "name": "Example RP"}
    server = Fido2Server(rp)
    user = {"id": b"user_id", "name": "A. User"}

    create_options, state = server.register_begin(
        user,
        resident_key_requirement="required",
        user_verification="required",
    )

    # Create a credential
    result = client.make_credential(
        {
            **create_options["publicKey"],
            "extensions": {"largeBlob": {"support": "required"}},
        }
    )
    auth_data = server.register_complete(state, result)
    credentials = [auth_data.credential_data]

    assert result.client_extension_results.large_blob.supported is True
    assert result.client_extension_results["largeBlob"]["supported"] is True

    request_options, state = server.authenticate_begin(
        credentials, user_verification="required"
    )

    data = b"test data"

    selection = client.get_assertion(
        {
            **request_options["publicKey"],
            # Write a large blob
            "extensions": {"largeBlob": {"write": websafe_encode(data)}},
        }
    )
    result = selection.get_response(0)

    assert result.client_extension_results.large_blob.written is True
    assert result.client_extension_results["largeBlob"]["written"] is True

    # Authenticate the credential
    selection = client.get_assertion(
        {
            **request_options["publicKey"],
            # Read back the blob
            "extensions": {"largeBlob": {"read": True}},
        }
    )
    result = selection.get_response(0)

    assert result.client_extension_results.large_blob.blob == data
    assert websafe_decode(result.client_extension_results["largeBlob"]["blob"]) == data

    # Clear the data
    lb = get_lb(ctap2, pin_protocol)
    lb.write_blob_array([])
    assert len(lb.read_blob_array()) == 0
