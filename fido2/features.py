from typing import Optional

import warnings


class FeatureNotEnabledError(Exception):
    pass


class _Feature:
    def __init__(self, name: str, desc: str):
        self._enabled: Optional[bool] = None
        self._name = name
        self._desc = desc

    @property
    def enabled(self) -> bool:
        self.warn()
        return self._enabled is True

    @enabled.setter
    def enabled(self, value: bool) -> None:
        if self._enabled is not None:
            raise ValueError(
                f"{self._name} has already been configured with {self._enabled}"
            )
        self._enabled = value

    def require(self, state=True) -> None:
        if self._enabled != state:
            self.warn()
            raise FeatureNotEnabledError(
                f"Usage requires {self._name}.enabled = {state}"
            )

    def warn(self) -> None:
        if self._enabled is None:
            warnings.warn(
                f"""Deprecated use of {self._name}.

You are using deprecated functionality which will change in the next major version of
python-fido2. You can opt-in to use the new functionality now by adding the following
to your code somewhere where it gets executed prior to using the affected functionality:

  import fido2.features
  fido2.features.{self._name}.enabled = True

To silence this warning but retain the current behavior, instead set enabled to False:
  fido2.features.{self._name}.enabled = False

{self._desc}
            """,
                DeprecationWarning,
            )


webauthn_json_mapping = _Feature(
    "webauthn_json_mapping",
    """JSON values for WebAuthn data class Mapping interface.

This changes the keys and values used by the webauthn data classes when accessed using
the Mapping (dict) interface (eg. user_entity["id"] and the from_dict() methods) to be
JSON-friendly and align with the current draft of the next WebAuthn Level specification.
For the most part, this means that binary values (bytes) are represented as URL-safe
base64 encoded strings instead.
""",
)
