import pytest

from fido2.client import ClientError, DefaultClientDataCollector, Fido2Client
from fido2.ctap import CtapError
from fido2.ctap2.bio import BioEnrollment, CaptureError, FPBioEnrollment
from fido2.ctap2.pin import ClientPin
from fido2.server import Fido2Server

from . import TEST_PIN, CliInteraction


@pytest.fixture(autouse=True, scope="module")
def preconditions(dev_manager):
    if not BioEnrollment.is_supported(dev_manager.info):
        pytest.skip("BioEnrollment not supported by authenticator")
    assert dev_manager.info.options["uv"] is False


def get_bio(ctap2, pin_protocol=None, permissions=ClientPin.PERMISSION.BIO_ENROLL):
    if pin_protocol:
        token = ClientPin(ctap2, pin_protocol).get_pin_token(TEST_PIN, permissions)
    else:
        token = None
    return FPBioEnrollment(ctap2, pin_protocol, token)


def test_get_sensor_info(ctap2):
    bio = get_bio(ctap2)
    info = bio.get_fingerprint_sensor_info()
    assert info.get(2) in (1, None)
    assert info.get(3, 1) > 0
    assert info.get(8, 1) > 0


def test_enroll_use_delete(device, ctap2, pin_protocol, printer):
    bio = get_bio(ctap2, pin_protocol)
    assert len(bio.enumerate_enrollments()) == 0

    context = bio.enroll()
    template_id = None
    while template_id is None:
        printer.print("Press your fingerprint against the sensor now...")
        try:
            template_id = context.capture()
            printer.print(f"{context.remaining} more scans needed.")
        except CaptureError as e:
            printer.print(e)

    enrollments = bio.enumerate_enrollments()
    assert len(enrollments) == 1
    assert enrollments[template_id] in ("", None)

    # Test name/rename
    info = bio.get_fingerprint_sensor_info()
    fname = "Test 1"
    bio.set_name(template_id, fname)

    enrollments = bio.enumerate_enrollments()
    assert len(enrollments) == 1
    assert enrollments[template_id] == fname

    fname = "Test".ljust(info.get(8, 0), "!")
    bio.set_name(template_id, fname)
    enrollments = bio.enumerate_enrollments()
    assert len(enrollments) == 1
    assert enrollments[template_id] == fname

    # Create a credential using fingerprint
    rp = {"id": "example.com", "name": "Example RP"}
    server = Fido2Server(rp)
    user = {"id": b"user_id", "name": "A. User"}
    create_options, state = server.register_begin(user, user_verification="required")

    client = Fido2Client(
        device,
        client_data_collector=DefaultClientDataCollector("https://example.com"),
        user_interaction=CliInteraction(printer, "WrongPin"),
    )

    # Allow multiple attempts
    for _ in range(3):
        try:
            result = client.make_credential(create_options.public_key)
            break
        except ClientError as e:
            if e.cause.code == CtapError.ERR.UV_INVALID:
                continue
            raise

    server.register_complete(state, result)

    # Delete fingerprint
    bio = get_bio(ctap2, pin_protocol)
    bio.remove_enrollment(template_id)
    assert len(bio.enumerate_enrollments()) == 0
