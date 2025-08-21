# Copyright (c) 2024 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""
Connects to the first FIDO device found which supports the PRF extension,
creates a new credential for it with the extension enabled, and uses it to
derive two separate secrets.
"""

import sys

from exampleutils import get_client

from fido2 import bls12_381, cbor
from fido2.cose import (
    ES256,
    ESP256,
    CoseKey,
    EcsdsaBls12_381_Bbs_Sha256,
    EcsdsaBls12_381_Sha256,
    EdDSA,
)
from fido2.server import Fido2Server
from fido2.utils import sha256, websafe_encode

ESP256_2P = -70009  # Placeholder value

uv = "discouraged"

# Locate a suitable FIDO authenticator
client, info = get_client(lambda info: "sign" in info.extensions)

server = Fido2Server({"id": "example.com", "name": "Example RP"}, attestation="none")
user = {"id": b"user_id", "name": "A. User"}

# Prepare parameters for makeCredential
create_options, state = server.register_begin(
    user,
    resident_key_requirement="discouraged",
    user_verification=uv,
    authenticator_attachment="cross-platform",
)

message = b"I am a message"
algorithms = [
    # ESP256_2P,
    EcsdsaBls12_381_Bbs_Sha256.ALGORITHM,
    EcsdsaBls12_381_Sha256.ALGORITHM,
]

has_prehash_alg = any(
    alg
    in [
        ESP256_2P,
    ]
    for alg in algorithms
)
has_raw_alg = any(
    alg
    in [
        EdDSA.ALGORITHM,
        ES256.ALGORITHM,
        ESP256.ALGORITHM,
        EcsdsaBls12_381_Sha256.ALGORITHM,
        EcsdsaBls12_381_Bbs_Sha256.ALGORITHM,
    ]
    for alg in algorithms
)

if has_prehash_alg and has_raw_alg:
    raise ValueError("Cannot mix algorithms with pre-hashed and raw message")

data = message if has_raw_alg else sha256(message)

# Create a credential
result = client.make_credential(
    {
        **create_options["publicKey"],
        "extensions": {
            "sign": {"generateKey": {"algorithms": algorithms, "tbs": data}}
        },
    }
)

# Complete registration
auth_data = server.register_complete(state, result)
credentials = [auth_data.credential_data]

# PRF result:
sign_result = result.client_extension_results.sign
print("CREATE sign result", sign_result)
sign_key = sign_result.generated_key
if not sign_key:
    print(
        "Failed to create credential with sign extension",
        result.client_extension_results,
    )
    sys.exit(1)
print("New credential created, with the sign extension.")
if sign_key.algorithm not in algorithms:
    print("Got unexpected algorithm in response:", sign_key.algorithm)
    sys.exit(1)


pk = CoseKey.parse(cbor.decode(sign_key.public_key))  # COSE key in bytes
print("public key", pk)
if "signature" in sign_result:
    print("Test verify signature", sign_result["signature"])
    pk.verify(message, sign_result.signature)
    print("Signature verified!")

crv = bls12_381.CRV_BLS
isk = crv.insecure_random_scalar()
ipk = crv.generator * isk
dpk = crv.point_from_cose(pk)
attrs = [None, *[crv.insecure_random_scalar() for _ in range(4)]]
attr_generators = [crv.generator, *[crv.insecure_random_point() for _ in attrs[1:]]]
A, e = bls12_381.split_bbs_sign(crv, isk, dpk, attrs[1:], attr_generators[1:])
disclose_idx = set([1, 3])
ctx = b"Daniluk-Lehmann"
(
    c_host,
    rr1,
    r1,
    rr2,
    r2,
    re,
    e,
    rai,
    attrs,
    disclose_idx,
    Abar,
    Bbar,
    D,
    t2prime,
    dpk,
) = bls12_381.begin_split_bbs_proof(
    A, e, dpk, attrs, attr_generators, ipk, disclose_idx, ctx
)

# t2prime = None
# t2prime = bls12_381.CRV_BLS.insecure_random_point()
t2px, t2py = (
    t2prime.to_affine().to_big_endian_coordinates()
    if t2prime is not None
    else (None, None)
)

kh = pk.get_ref()
kh[3] = sign_key.algorithm
if pk[1] == 2:  # EC2
    kh[-1] = pk[-1]  # crv
if t2prime is not None:
    kh[-10] = {
        1: 2,
        -1: pk[-1],
        -2: t2px,
        -3: t2py,
    }
kh_bin = cbor.encode(kh)  # key handle in bytes
print("keyHandle", kh)

message = c_host
data = message if has_raw_alg else sha256(message)

# Prepare parameters for getAssertion
request_options, state = server.authenticate_begin(credentials, user_verification=uv)

# Authenticate the credential
result = client.get_assertion(
    {
        **request_options["publicKey"],
        "extensions": {
            "sign": {
                "sign": {
                    "tbs": data,
                    "keyHandleByCredential": {
                        websafe_encode(credentials[0].credential_id): kh_bin,
                    },
                },
            }
        },
    }
)

# Only one cred in allowCredentials, only one response.
result = result.get_response(0)

sign_result = result.client_extension_results.sign
print("GET sign result", sign_result)

print("Test verify signature", sign_result.get("signature"))

pk.verify(message, sign_result.signature, t2prime)
print("Signature verified!")


signature = sign_result.signature
assert len(signature) == crv.scalar_len * 3  # noqa: S101
sa0 = int.from_bytes(signature[: crv.scalar_len], "big")
c = signature[crv.scalar_len : crv.scalar_len * 2]
n = signature[crv.scalar_len * 2 :]


Abar, Bbar, D, c, sr1, sr2, se, sai, n = bls12_381.finish_split_bbs_proof(
    c_host,
    rr1,
    r1,
    rr2,
    r2,
    re,
    e,
    rai,
    attrs,
    disclose_idx,
    Abar,
    Bbar,
    D,
    sa0,
    c,
    n,
    t2prime,
    dpk,
)

verified = bls12_381.verify_split_bbs_proof(
    Abar,
    Bbar,
    D,
    c,
    sr1,
    sr2,
    se,
    sai,
    ipk,
    disclose_idx,
    [attrs[i] if i in disclose_idx else None for i in range(len(attrs))],
    attr_generators,
    ctx,
    n,
)

print("Split-BBS proof verified:", verified)
