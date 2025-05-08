from fido2.webauthn import Aaguid


def assert_list_of(typ, value):
    assert isinstance(value, list)
    for v in value:
        assert isinstance(v, typ)


def assert_dict_of(k_type, v_type, value):
    assert isinstance(value, dict)
    for k, v in value.items():
        assert isinstance(k, k_type)
        assert isinstance(v, v_type)


def assert_unique(value):
    assert len(set(value)) == len(value)


def test_get_info_fields(ctap2):
    info = ctap2.get_info()

    assert_list_of(str, info.versions)
    assert len(info.versions) > 0

    assert_list_of(str, info.extensions)
    assert isinstance(info.aaguid, Aaguid)
    assert_dict_of(str, bool | None, info.options)
    assert isinstance(info.max_msg_size, int)
    assert_list_of(int, info.pin_uv_protocols)
    assert_unique(info.pin_uv_protocols)
    assert isinstance(info.max_creds_in_list, int)
    assert isinstance(info.max_cred_id_length, int)
    assert_list_of(str, info.transports)
    assert_unique(info.transports)

    assert_list_of(dict, info.algorithms)
    assert isinstance(info.max_large_blob, int)
    assert isinstance(info.force_pin_change, bool)
    assert isinstance(info.min_pin_length, int)
    assert info.min_pin_length >= 4
    assert isinstance(info.firmware_version, int)
    assert isinstance(info.max_cred_blob_length, int)
    assert isinstance(info.max_rpids_for_min_pin, int)
    assert isinstance(info.preferred_platform_uv_attempts, int)
    assert isinstance(info.uv_modality, int)
    assert_dict_of(str, int, info.certifications)

    assert isinstance(info.remaining_disc_creds, int | None)
    assert_list_of(int, info.vendor_prototype_config_commands)
    assert_list_of(str, info.attestation_formats)
    assert_unique(info.attestation_formats)
    assert len(info.attestation_formats) > 0

    assert isinstance(info.uv_count_since_pin, int | None)
    assert isinstance(info.long_touch_for_reset, bool)


def test_enc_identifier_changes(ctap2):
    if ctap2.info.enc_identifier:
        assert ctap2.get_info().enc_identifier != ctap2.get_info().enc_identifier
