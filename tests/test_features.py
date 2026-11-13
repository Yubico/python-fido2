import pytest

from fido2.features import FeatureNotEnabledError, _Feature


def test_enabled_warns_at_caller():
    feature = _Feature("test_feature", "Test feature.")
    with pytest.warns(DeprecationWarning) as record:
        assert feature.enabled is False
    assert record[0].filename == __file__


def test_require_warns_at_caller():
    feature = _Feature("test_feature", "Test feature.")
    with pytest.warns(DeprecationWarning) as record:
        with pytest.raises(FeatureNotEnabledError):
            feature.require()
    assert record[0].filename == __file__
