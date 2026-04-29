import os
from collections.abc import Callable
from enum import IntEnum
from importlib.metadata import version
from typing import Mapping, cast

import cryptography.exceptions
import pytest
from fido2 import cbor
from fido2.cose import ESP256_SPLIT_ARKG_PLACEHOLDER, CoseKey
from fido2.ctap import CtapError
from fido2.ctap2.pin import ClientPin
from fido2.utils import sha256
from fido2.webauthn import AttestationObject

from . import TEST_PIN


@pytest.fixture(autouse=True, scope="module")
def check_arkg_support():
    if int(version("cryptography").split(".")[0]) < 45:
        pytest.skip("ARKG support requires cryptography 45 or later")


class AuthenticatorInput(IntEnum):
    KH = 2
    ALG = 3
    FLAGS = 4
    TBS = 6
    ARGS = 7


class AuthenticatorOutput(IntEnum):
    ALG = 3
    FLAGS = 4
    SIG = 6
    ATT_OBJ = 7


EMPTY_JSON_HASH = sha256(b"{}")
RP = {"id": "example.com", "name": "Example RP"}
USER = {"id": b"user_id", "name": "A. User"}
"""Not truly _all_ algorithms, but all we have prototyped"""
ALL_ALGORITHMS = [
    -9,  # ESP256
    -7,  # ES256
    -300,  # Requested assignment for ESP256-split https://www.ietf.org/archive/id/draft-lundberg-cose-two-party-signing-algs-06.html#name-ecdsa
    -70009,  # Placeholder value for ESP256-split used by some prototypes
    ESP256_SPLIT_ARKG_PLACEHOLDER,  # Placeholder for ESP256-split-ARKG https://www.ietf.org/archive/id/draft-bradleylundberg-cfrg-arkg-10.html#name-cose-algorithms
]
PREHASH_ALGS = [
    ESP256_SPLIT_ARKG_PLACEHOLDER,
    -300,
    -70009,  # Placeholder value for ESP256-split used by some prototypes
]


# These tests use only the raw authenticator inputs/outputs so the
# python-fido2 library doesn't need to maintain backwards compatibility of
# the client layer of the extension.


@pytest.fixture(autouse=True, scope="module")
def preconditions(dev_manager):
    if "previewSign" not in dev_manager.info.extensions:
        pytest.skip("previewSign not supported by authenticator")


def generate_key_inputs(algorithms, flags=0b000):
    return {
        AuthenticatorInput.ALG: algorithms,
        AuthenticatorInput.FLAGS: flags,
    }


def parse_generate_key_outputs(response):
    exts = response.auth_data.extensions or {}
    if "previewSign" in exts:
        assert AuthenticatorOutput.ALG in exts["previewSign"]
        algorithm = exts["previewSign"][AuthenticatorOutput.ALG]
        assert "previewSign" in response.unsigned_extension_outputs
        unsigned_outputs = response.unsigned_extension_outputs["previewSign"]

        assert AuthenticatorOutput.ATT_OBJ in unsigned_outputs
        att_obj_cbor = cast(
            Mapping, cbor.decode(unsigned_outputs[AuthenticatorOutput.ATT_OBJ])
        )
        att_obj = AttestationObject.create(
            att_obj_cbor[1], att_obj_cbor[2], att_obj_cbor[3]
        )

        key_handle = att_obj.auth_data.credential_data.credential_id
        public_key = att_obj.auth_data.credential_data.public_key
        return algorithm, key_handle, public_key, att_obj

    else:
        return None


def sign_inputs(cred, tbs, additional_args=None):
    sign_inputs = {
        AuthenticatorInput.KH: cred.key_handle,
        AuthenticatorInput.TBS: sha256(tbs) if cred.algorithm in PREHASH_ALGS else tbs,
    }
    if additional_args is not None:
        sign_inputs[AuthenticatorInput.ARGS] = cbor.encode(additional_args)
    return sign_inputs


def parse_sign_outputs(response):
    exts = response.auth_data.extensions
    if "previewSign" in exts and AuthenticatorOutput.SIG in exts["previewSign"]:
        signature = exts["previewSign"][AuthenticatorOutput.SIG]
        return signature

    else:
        return None


class Credential:
    def __init__(
        self,
        response,
        flags: int,
        options,
        extensions,
        generated_key: tuple[int, bytes, CoseKey, AttestationObject],
    ):
        self.response = response
        self.flags = flags
        self.options = options
        self.extensions = extensions
        algorithm, key_handle, public_key, att_obj = generated_key or [None] * 4
        self.algorithm = algorithm
        self.key_handle = key_handle
        self.public_key = public_key
        self.att_obj = att_obj

    def __repr__(self):
        return repr(
            (
                self.response,
                self.flags,
                self.options,
                self.extensions,
                self.algorithm,
                self.key_handle,
                self.public_key,
                self.att_obj,
            )
        )


class CredentialCache:
    def __init__(self, generate_key):
        self.generate_key = generate_key
        self.cache = []

    def make_cred(
        self,
        cache_filter: Callable[[Credential], bool],
        algorithms: list[int],
        flags=0b000,
        options=None,
        extensions={},
    ) -> Credential | None:
        existing = next((cred for cred in self.cache if cache_filter(cred)), None)
        if existing is not None:
            return existing
        else:
            cred = self.generate_key(algorithms, flags, options, extensions)
            self.cache.append(cred)
            return cred

    def make_cred_or_skip(self, cache_filter, algorithms, *args, **kwargs):
        try:
            return self.make_cred(cache_filter, algorithms, *args, **kwargs)
        except CtapError as e:
            if e.code == CtapError.ERR.UNSUPPORTED_ALGORITHM:
                pytest.skip(f"Algorithms {algorithms} not supported")
            raise e


@pytest.fixture(scope="module")
def credential_cache(generate_key):
    return CredentialCache(generate_key)


@pytest.fixture(scope="module")
def generate_key(dev_manager):
    def make_cred(
        algorithms: list[int],
        flags=0b000,
        options=None,
        extensions={},
    ) -> Credential:
        ext_inputs = generate_key_inputs(algorithms, flags)

        pin_protocol = None
        pin_uv_param = None
        if options is not None and options["rk"]:
            client_pin = ClientPin(dev_manager.ctap2)
            pin_protocol = client_pin.protocol.VERSION
            pin_token = client_pin.get_pin_token(TEST_PIN)
            pin_uv_param = client_pin.protocol.authenticate(pin_token, EMPTY_JSON_HASH)

        response = dev_manager.ctap2.make_credential(
            EMPTY_JSON_HASH,
            RP,
            USER,
            [{"type": "public-key", "alg": -7}],
            options=options,
            extensions={"previewSign": ext_inputs, **extensions},
            pin_uv_param=pin_uv_param,
            pin_uv_protocol=pin_protocol,
            on_keepalive=dev_manager.on_keepalive,
        )
        return Credential(
            response, flags, options, extensions, parse_generate_key_outputs(response)
        )

    return make_cred


@pytest.fixture(scope="module")
def sign(dev_manager):
    def get_assertion(
        cred: Credential,
        tbs,
        additional_args=None,
        up=False,
    ):
        ext_inputs = sign_inputs(cred, tbs, additional_args)
        response = dev_manager.ctap2.get_assertion(
            RP["id"],
            EMPTY_JSON_HASH,
            allow_list=[
                {
                    "type": "public-key",
                    "id": cred.response.auth_data.credential_data.credential_id,
                }
            ],
            options={"up": up},
            extensions={"previewSign": ext_inputs},
            on_keepalive=dev_manager.on_keepalive,
        )
        return (
            response,
            parse_sign_outputs(response),
        )

    return get_assertion


def if_arkg(algorithm, public_key):
    if algorithm == -65539:
        arkg_pub_seed = public_key
        assert arkg_pub_seed[3] == -65700, "Expected alg: ARKG-P256"
        assert arkg_pub_seed[-3] == -9, "Expected dkalg: ESP256"
        arkg_ikm = os.urandom(32)
        arkg_ctx = b"python-fido2.test_sign_extension_v4"
        return arkg_pub_seed.derive_public_key(arkg_ikm, arkg_ctx)
    else:
        return public_key, None


def test_esp256_split(credential_cache, sign):
    algorithms = [
        -300,  # Requested assignment for ESP256-split https://www.ietf.org/archive/id/draft-lundberg-cose-two-party-signing-algs-06.html#name-ecdsa
        -70009,  # Placeholder value used by some prototypes
    ]
    cred = credential_cache.make_cred_or_skip(
        lambda cred: cred.algorithm in algorithms and cred.flags == 0b000,
        algorithms,
    )
    assert cred.algorithm in algorithms

    tbs = os.urandom(32)
    response, signature = sign(cred, tbs)

    assert signature is not None
    cred.public_key.verify(tbs, signature)


def test_esp256(credential_cache, sign):
    algorithms = [-9]
    cred = credential_cache.make_cred_or_skip(
        lambda cred: cred.algorithm in algorithms and cred.flags == 0b000,
        algorithms,
    )
    assert cred.algorithm in algorithms

    tbs = os.urandom(32)
    response, signature = sign(cred, tbs)

    assert signature is not None
    cred.public_key.verify(tbs, signature)


def test_es256(credential_cache, sign):
    algorithms = [-7]
    cred = credential_cache.make_cred_or_skip(
        lambda cred: cred.algorithm in algorithms and cred.flags == 0b000,
        algorithms,
    )
    assert cred.algorithm in algorithms

    tbs = os.urandom(32)
    response, signature = sign(cred, tbs)

    assert signature is not None
    cred.public_key.verify(tbs, signature)


def test_esp256_split_arkg(credential_cache, sign):
    algorithms = [
        -65539,  # Placeholder for ESP256-split-ARKG https://www.ietf.org/archive/id/draft-bradleylundberg-cfrg-arkg-10.html#name-cose-algorithms
    ]
    cred = credential_cache.make_cred_or_skip(
        lambda cred: cred.algorithm in algorithms and cred.flags == 0b000,
        algorithms,
    )
    assert cred.algorithm in algorithms

    public_key, args = if_arkg(cred.algorithm, cred.public_key)

    tbs = os.urandom(32)
    response, signature = sign(cred, tbs, additional_args=args)

    assert signature is not None
    public_key.verify(tbs, signature)


def test_two_keys_same_alg(credential_cache, sign):
    algorithms = ALL_ALGORITHMS
    cred = credential_cache.make_cred_or_skip(
        lambda cred: cred.algorithm in algorithms and cred.flags == 0b000,
        algorithms,
    )
    assert cred.algorithm in algorithms

    algorithms2 = [cred.algorithm]
    cred2 = credential_cache.make_cred_or_skip(
        lambda cred2: (
            cred2.algorithm == cred.algorithm
            and cred2.flags == 0b000
            and cred2.response.auth_data.credential_data.credential_id
            != cred.response.auth_data.credential_data.credential_id
        ),
        algorithms2,
    )
    assert cred2 is not None

    public_key, args = if_arkg(cred.algorithm, cred.public_key)

    tbs = os.urandom(32)
    response, signature = sign(cred, tbs, additional_args=args)

    assert signature is not None
    public_key.verify(tbs, signature)

    public_key2, _ = if_arkg(cred2.algorithm, cred2.public_key)

    assert cred2.algorithm in algorithms2
    assert cred2.algorithm == cred.algorithm
    assert cred2.key_handle != cred.key_handle
    assert cred2.public_key != cred.public_key
    assert cred2.att_obj != cred.att_obj

    with pytest.raises(cryptography.exceptions.InvalidSignature):
        public_key2.verify(tbs, signature)


def test_two_keys_different_alg(credential_cache, sign):
    algorithms = ALL_ALGORITHMS
    cred = credential_cache.make_cred_or_skip(
        lambda cred: cred.algorithm in algorithms and cred.flags == 0b000,
        algorithms,
    )
    assert cred.algorithm in algorithms

    algorithms2 = [alg for alg in algorithms if alg != cred.algorithm]
    cred2 = credential_cache.make_cred_or_skip(
        lambda cred2: (
            cred2.algorithm in algorithms2
            and cred2.flags == 0b000
            and cred2.response.auth_data.credential_data.credential_id
            != cred.response.auth_data.credential_data.credential_id
            and cred2.algorithm != cred.algorithm
        ),
        algorithms2,
    )
    assert cred2 is not None

    public_key, args = if_arkg(cred.algorithm, cred.public_key)

    tbs = os.urandom(32)
    response, signature = sign(cred, tbs, additional_args=args)

    assert signature is not None
    public_key.verify(tbs, signature)

    public_key2, _ = if_arkg(cred2.algorithm, cred2.public_key)

    assert cred2.algorithm in algorithms2
    assert cred2.key_handle != cred.key_handle
    assert cred2.public_key != cred.public_key
    assert cred2.att_obj != cred.att_obj

    with pytest.raises(cryptography.exceptions.InvalidSignature):
        public_key2.verify(tbs, signature)


def test_register_unsupported_alg(generate_key):
    algorithms = [
        -18,  # SHAKE128, nonsensical value in this context
    ]
    with pytest.raises(CtapError) as exc_info:
        generate_key(algorithms)
    assert exc_info.value.code == CtapError.ERR.UNSUPPORTED_ALGORITHM


@pytest.mark.parametrize("flags", range(0, 256))
def test_register_invalid_flags(generate_key, flags):
    if flags in [0b000, 0b001, 0b101]:
        generate_key(ALL_ALGORITHMS, flags=flags)
    else:
        with pytest.raises(CtapError) as exc_info:
            generate_key(ALL_ALGORITHMS, flags=flags)

        assert exc_info.value.code == CtapError.ERR.INVALID_OPTION


def test_assert_empty_allow_list(ctap2, on_keepalive, credential_cache):
    cred = credential_cache.make_cred_or_skip(
        lambda cred: (
            cred.flags == 0b000
            and (cred.options or {}).get("rk", False)
            and (cred.extensions or {}).get("credProtect", None) == 0x01
        ),
        ALL_ALGORITHMS,
        options={"rk": True},  # Required for allow_list=None to succees
        extensions={"credProtect": 0x01},  # Required for allow_list=None with up=False
    )
    tbs = os.urandom(32)
    public_key, args = if_arkg(cred.algorithm, cred.public_key)
    ext_inputs = sign_inputs(cred, tbs, additional_args=args)

    response1 = ctap2.get_assertion(
        RP["id"],
        EMPTY_JSON_HASH,
        allow_list=None,
        options={"up": False},
        extensions=None,
        on_keepalive=on_keepalive,
    )
    assert response1 is not None

    with pytest.raises(CtapError) as exc_info:
        ctap2.get_assertion(
            RP["id"],
            EMPTY_JSON_HASH,
            allow_list=None,
            options={"up": False},
            extensions={"previewSign": ext_inputs},
            on_keepalive=on_keepalive,
        )
    assert exc_info.value.code == CtapError.ERR.INVALID_OPTION


@pytest.mark.parametrize("missing_key", [AuthenticatorInput.KH, AuthenticatorInput.TBS])
def test_assert_missing_required_parameter(
    ctap2, on_keepalive, credential_cache, missing_key
):
    cred = credential_cache.make_cred_or_skip(
        lambda cred: cred.flags == 0b000, ALL_ALGORITHMS
    )
    credential_id = cred.response.auth_data.credential_data.credential_id
    tbs = os.urandom(32)
    public_key, args = if_arkg(cred.algorithm, cred.public_key)
    ext_inputs = sign_inputs(cred, tbs, additional_args=args)

    response1 = ctap2.get_assertion(
        RP["id"],
        EMPTY_JSON_HASH,
        allow_list=[{"type": "public-key", "id": credential_id}],
        options={"up": False},
        extensions={"previewSign": ext_inputs},
        on_keepalive=on_keepalive,
    )
    assert response1 is not None

    mod_ext_inputs = {**ext_inputs}
    del mod_ext_inputs[missing_key]
    with pytest.raises(CtapError) as exc_info:
        ctap2.get_assertion(
            RP["id"],
            EMPTY_JSON_HASH,
            allow_list=[{"type": "public-key", "id": credential_id}],
            options={"up": False},
            extensions={"previewSign": mod_ext_inputs},
            on_keepalive=on_keepalive,
        )
    assert exc_info.value.code == CtapError.ERR.INVALID_OPTION


def test_assert_missing_args_alg(ctap2, on_keepalive, credential_cache):
    cred = credential_cache.make_cred_or_skip(
        lambda cred: (
            cred.algorithm == ESP256_SPLIT_ARKG_PLACEHOLDER and cred.flags == 0b000
        ),
        [ESP256_SPLIT_ARKG_PLACEHOLDER],
    )
    credential_id = cred.response.auth_data.credential_data.credential_id
    tbs = os.urandom(32)
    public_key, args = if_arkg(cred.algorithm, cred.public_key)
    if args is None:
        pytest.skip("Algorithm does not use additional arguments")
    ext_inputs = sign_inputs(cred, tbs, additional_args=args)

    response1 = ctap2.get_assertion(
        RP["id"],
        EMPTY_JSON_HASH,
        allow_list=[{"type": "public-key", "id": credential_id}],
        options={"up": False},
        extensions={"previewSign": ext_inputs},
        on_keepalive=on_keepalive,
    )
    assert response1 is not None

    del args[AuthenticatorInput.ALG]
    ext_inputs = sign_inputs(cred, tbs, additional_args=args)

    with pytest.raises(CtapError) as exc_info:
        ctap2.get_assertion(
            RP["id"],
            EMPTY_JSON_HASH,
            allow_list=[{"type": "public-key", "id": credential_id}],
            options={"up": False},
            extensions={"previewSign": ext_inputs},
            on_keepalive=on_keepalive,
        )
    assert exc_info.value.code == CtapError.ERR.INVALID_CREDENTIAL


def test_assert_incorrect_args_alg(ctap2, on_keepalive, credential_cache):
    cred = credential_cache.make_cred_or_skip(
        lambda cred: (
            cred.algorithm == ESP256_SPLIT_ARKG_PLACEHOLDER and cred.flags == 0b000
        ),
        [ESP256_SPLIT_ARKG_PLACEHOLDER],
    )
    credential_id = cred.response.auth_data.credential_data.credential_id
    tbs = os.urandom(32)
    public_key, args = if_arkg(cred.algorithm, cred.public_key)
    if args is None:
        pytest.skip("Algorithm does not use additional arguments")
    ext_inputs = sign_inputs(cred, tbs, additional_args=args)

    response1 = ctap2.get_assertion(
        RP["id"],
        EMPTY_JSON_HASH,
        allow_list=[{"type": "public-key", "id": credential_id}],
        options={"up": False},
        extensions={"previewSign": ext_inputs},
        on_keepalive=on_keepalive,
    )
    assert response1 is not None

    args[AuthenticatorInput.ALG] += 1
    ext_inputs = sign_inputs(cred, tbs, additional_args=args)

    with pytest.raises(CtapError) as exc_info:
        ctap2.get_assertion(
            RP["id"],
            EMPTY_JSON_HASH,
            allow_list=[{"type": "public-key", "id": credential_id}],
            options={"up": False},
            extensions={"previewSign": ext_inputs},
            on_keepalive=on_keepalive,
        )
    assert exc_info.value.code == CtapError.ERR.INVALID_CREDENTIAL


def test_assert_missing_args(ctap2, on_keepalive, credential_cache, sign):
    cred = credential_cache.make_cred_or_skip(
        lambda cred: (
            cred.algorithm == ESP256_SPLIT_ARKG_PLACEHOLDER and cred.flags == 0b000
        ),
        [ESP256_SPLIT_ARKG_PLACEHOLDER],
    )
    tbs = os.urandom(32)
    public_key, args = if_arkg(cred.algorithm, cred.public_key)
    if args is None:
        pytest.skip("Algorithm does not use additional arguments")
    sign_inputs(cred, tbs, additional_args=args)

    response1 = sign(cred, tbs, additional_args=args)
    assert response1 is not None

    with pytest.raises(CtapError) as exc_info:
        sign(cred, tbs, additional_args=None)
    assert exc_info.value.code == CtapError.ERR.MISSING_PARAMETER


def test_assert_unknown_args(ctap2, on_keepalive, credential_cache, sign):
    cred = credential_cache.make_cred_or_skip(
        lambda cred: (
            cred.algorithm == ESP256_SPLIT_ARKG_PLACEHOLDER and cred.flags == 0b000
        ),
        [ESP256_SPLIT_ARKG_PLACEHOLDER],
    )
    tbs = os.urandom(32)
    public_key, args = if_arkg(cred.algorithm, cred.public_key)
    if args is None:
        pytest.skip("Algorithm does not use additional arguments")

    response1 = sign(cred, tbs, additional_args=args)
    assert response1 is not None

    response2 = sign(cred, tbs, additional_args={**args, 42: 1337})
    assert response2 is not None


def test_assert_up_required(ctap2, on_keepalive, credential_cache, sign):
    cred = credential_cache.make_cred_or_skip(
        lambda cred: cred.flags & 0b001 == 0b001,
        ALL_ALGORITHMS,
        flags=0b001,
    )
    tbs = os.urandom(32)
    public_key, args = if_arkg(cred.algorithm, cred.public_key)

    with pytest.raises(CtapError) as exc_info:
        sign(cred, tbs, additional_args=args, up=False)
    assert exc_info.value.code == CtapError.ERR.UP_REQUIRED


def test_assert_uv_required(ctap2, on_keepalive, credential_cache, sign):
    cred = credential_cache.make_cred_or_skip(
        lambda cred: cred.flags == 0b101,
        ALL_ALGORITHMS,
        flags=0b101,
    )
    tbs = os.urandom(32)
    public_key, args = if_arkg(cred.algorithm, cred.public_key)

    with pytest.raises(CtapError) as exc_info:
        sign(cred, tbs, additional_args=args, up=True)
    assert exc_info.value.code == CtapError.ERR.PUAT_REQUIRED
