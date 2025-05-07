# Copyright (c) 2025 Yubico AB
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

# flake8: noqa ignore lines too long


import pytest


@pytest.fixture(autouse=True, scope="module")
def preconditions():
    global ARKG_P256
    try:
        from fido2.arkg import ARKG_P256
    except ImportError:
        pytest.skip("ecdsa is not installed")


TEST_VECTORS = [
    {
        "ctx": b"ARKG-P256.test vectors",
        "ikm_bl": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "ikm_kem": "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        "ikm": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
        "pk_bl": "046d3bdf31d0db48988f16d47048fdd24123cd286e42d0512daa9f726b4ecf18df65ed42169c69675f936ff7de5f9bd93adbc8ea73036b16e8d90adbfabdaddba7",
        "pk_kem": "04c38bbdd7286196733fa177e43b73cfd3d6d72cd11cc0bb2c9236cf85a42dcff5dfa339c1e07dfcdfda8d7be2a5a3c7382991f387dfe332b1dd8da6e0622cfb35",
        "sk_bl": "d959500a78ccf850ce46c80a8c5043c9a2e33844232b3829df37d05b3069f455",
        "sk_kem": "74e0a4cd81ca2d24246ff75bfd6d4fb7f9dfc938372627feb2c2348f8b1493b5",
        "pk_prime": "04572a111ce5cfd2a67d56a0f7c684184b16ccd212490dc9c5b579df749647d107dac2a1b197cc10d2376559ad6df6bc107318d5cfb90def9f4a1f5347e086c2cd",
        "sk_prime": "775d7fe9a6dfba43ce671cb38afca3d272c4d14aff97bd67559eb500a092e5e7",
    },
    {
        "ctx": b"ARKG-P256.test vectors",
        "ikm_bl": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "ikm_kem": "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        "ikm": "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
        "pk_bl": "046d3bdf31d0db48988f16d47048fdd24123cd286e42d0512daa9f726b4ecf18df65ed42169c69675f936ff7de5f9bd93adbc8ea73036b16e8d90adbfabdaddba7",
        "pk_kem": "04c38bbdd7286196733fa177e43b73cfd3d6d72cd11cc0bb2c9236cf85a42dcff5dfa339c1e07dfcdfda8d7be2a5a3c7382991f387dfe332b1dd8da6e0622cfb35",
        "sk_bl": "d959500a78ccf850ce46c80a8c5043c9a2e33844232b3829df37d05b3069f455",
        "sk_kem": "74e0a4cd81ca2d24246ff75bfd6d4fb7f9dfc938372627feb2c2348f8b1493b5",
        "pk_prime": "04ea7d962c9f44ffe8b18f1058a471f394ef81b674948eefc1865b5c021cf858f577f9632b84220e4a1444a20b9430b86731c37e4dcb285eda38d76bf758918d86",
        "sk_prime": "6228e470290e9d7cc0feff32a74caafa14c608c956337eba23997f5904cff226",
    },
    {
        "ctx": b"ARKG-P256.test vectors.0",
        "ikm_bl": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "ikm_kem": "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        "ikm": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
        "pk_bl": "046d3bdf31d0db48988f16d47048fdd24123cd286e42d0512daa9f726b4ecf18df65ed42169c69675f936ff7de5f9bd93adbc8ea73036b16e8d90adbfabdaddba7",
        "pk_kem": "04c38bbdd7286196733fa177e43b73cfd3d6d72cd11cc0bb2c9236cf85a42dcff5dfa339c1e07dfcdfda8d7be2a5a3c7382991f387dfe332b1dd8da6e0622cfb35",
        "sk_bl": "d959500a78ccf850ce46c80a8c5043c9a2e33844232b3829df37d05b3069f455",
        "sk_kem": "74e0a4cd81ca2d24246ff75bfd6d4fb7f9dfc938372627feb2c2348f8b1493b5",
        "pk_prime": "04b79b65d6bbb419ff97006a1bd52e3f4ad53042173992423e06e52987a037cb61dd82b126b162e4e7e8dc5c9fd86e82769d402a1968c7c547ef53ae4f96e10b0e",
        "sk_prime": "2a97f4232f9abba32fbfc28c6686f8afd2d851c2a95a3ed2f0a384b9ad55068d",
    },
]
# Convert hex strings to bytes
TEST_VECTORS = [
    {k: bytes.fromhex(v) if k != "ctx" else v for k, v in tv.items()}
    for tv in TEST_VECTORS
]


@pytest.mark.parametrize("test_vector", TEST_VECTORS)
def test_vectors(test_vector):
    pub_key = ARKG_P256(
        {
            1: -65537,
            2: b"implementation-specific-keyhandle",
            3: -65700,
            -1: {
                1: 2,
                3: -7,
                -1: 1,
                -2: test_vector["pk_bl"][1:33],
                -3: test_vector["pk_bl"][33:65],
            },
            -2: {
                1: 2,
                3: -25,
                -1: 1,
                -2: test_vector["pk_kem"][1:33],
                -3: test_vector["pk_kem"][33:65],
            },
            -3: -9,
        }
    )

    pk_derived = pub_key.derive_public_key(test_vector["ikm"], test_vector["ctx"])
    point = b"\4" + pk_derived[-2] + pk_derived[-3]
    assert point.hex() == test_vector["pk_prime"].hex()
