# flake8: noqa ignore lines too long
from fido2.arkg import ARKG_P256

import pytest


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
        "ikm": "00",
        "pk_bl": "046d3bdf31d0db48988f16d47048fdd24123cd286e42d0512daa9f726b4ecf18df65ed42169c69675f936ff7de5f9bd93adbc8ea73036b16e8d90adbfabdaddba7",
        "pk_kem": "04c38bbdd7286196733fa177e43b73cfd3d6d72cd11cc0bb2c9236cf85a42dcff5dfa339c1e07dfcdfda8d7be2a5a3c7382991f387dfe332b1dd8da6e0622cfb35",
        "sk_bl": "d959500a78ccf850ce46c80a8c5043c9a2e33844232b3829df37d05b3069f455",
        "sk_kem": "74e0a4cd81ca2d24246ff75bfd6d4fb7f9dfc938372627feb2c2348f8b1493b5",
        "pk_prime": "040e983f44cafa9036066857d1831b58cc2227677489df07d1ae0801259ddc0a6aa77f98712ecf662773ef73b6414d752bab57288cdce1299f73e606306bf77c54",
        "sk_prime": "298271791090c1a0f3ef346a974b8daeab2876f2943207b2cddfe4ddff7a6295",
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
    {
        "ctx": b"ARKG-P256.test vectors.0",
        "ikm_bl": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "ikm_kem": "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        "ikm": "00",
        "pk_bl": "046d3bdf31d0db48988f16d47048fdd24123cd286e42d0512daa9f726b4ecf18df65ed42169c69675f936ff7de5f9bd93adbc8ea73036b16e8d90adbfabdaddba7",
        "pk_kem": "04c38bbdd7286196733fa177e43b73cfd3d6d72cd11cc0bb2c9236cf85a42dcff5dfa339c1e07dfcdfda8d7be2a5a3c7382991f387dfe332b1dd8da6e0622cfb35",
        "sk_bl": "d959500a78ccf850ce46c80a8c5043c9a2e33844232b3829df37d05b3069f455",
        "sk_kem": "74e0a4cd81ca2d24246ff75bfd6d4fb7f9dfc938372627feb2c2348f8b1493b5",
        "pk_prime": "04dfd47f9357efc0146e243c2cab4601c250b792111d6a364587a728d5624cfaf16e62dbf37ebc132537038f5daa2ff6cd38f229fd3063c618b4333cea35af6e85",
        "sk_prime": "e5e0fab3367300dc45904128a3f8991a9d9059b585aac29e6f4e7cb45f59fce0",
    },
    {
        "ctx": b"ARKG-P256.test vectors.1",
        "ikm_bl": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "ikm_kem": "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        "ikm": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
        "pk_bl": "046d3bdf31d0db48988f16d47048fdd24123cd286e42d0512daa9f726b4ecf18df65ed42169c69675f936ff7de5f9bd93adbc8ea73036b16e8d90adbfabdaddba7",
        "pk_kem": "04c38bbdd7286196733fa177e43b73cfd3d6d72cd11cc0bb2c9236cf85a42dcff5dfa339c1e07dfcdfda8d7be2a5a3c7382991f387dfe332b1dd8da6e0622cfb35",
        "sk_bl": "d959500a78ccf850ce46c80a8c5043c9a2e33844232b3829df37d05b3069f455",
        "sk_kem": "74e0a4cd81ca2d24246ff75bfd6d4fb7f9dfc938372627feb2c2348f8b1493b5",
        "pk_prime": "04cc85763fae2c8f38964ddc1f3dd9eebe2d2cb5c2842b0a622939b608f9cef967aafa50b9b24d6ae5a273f5b5d03b6a1ce8abd4f4dbaf487c417ef7380d1481b5",
        "sk_prime": "1a60b7fe69b315fe1262c46711af990d47228471ef5a296f6aa26ba6a5a1a6ec",
    },
    {
        "ctx": b"ARKG-P256.test vectors.1",
        "ikm_bl": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "ikm_kem": "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        "ikm": "00",
        "pk_bl": "046d3bdf31d0db48988f16d47048fdd24123cd286e42d0512daa9f726b4ecf18df65ed42169c69675f936ff7de5f9bd93adbc8ea73036b16e8d90adbfabdaddba7",
        "pk_kem": "04c38bbdd7286196733fa177e43b73cfd3d6d72cd11cc0bb2c9236cf85a42dcff5dfa339c1e07dfcdfda8d7be2a5a3c7382991f387dfe332b1dd8da6e0622cfb35",
        "sk_bl": "d959500a78ccf850ce46c80a8c5043c9a2e33844232b3829df37d05b3069f455",
        "sk_kem": "74e0a4cd81ca2d24246ff75bfd6d4fb7f9dfc938372627feb2c2348f8b1493b5",
        "pk_prime": "04056c654c97ea460ebfae997c8e12314184e45183aefdb8ce9547afca1faaee70da6c6433c8fe71c32284cf0a015eb463ea2fc81438f6698684525f011d7ae83c",
        "sk_prime": "bb609831741d9232ecd7d58770c503992ca78d34361a865a0d6715861955526f",
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
