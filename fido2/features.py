# Copyright (c) 2022 Yubico AB
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


import warnings
from functools import wraps
from inspect import Parameter, signature
from typing import Any, Callable, ParamSpec, TypeVar

P = ParamSpec("P")
R = TypeVar("R")


class FeatureNotEnabledError(Exception):
    pass


class _Feature:
    def __init__(self, name: str, desc: str):
        self._enabled: bool | None = None
        self._name = name
        self._desc = desc

    @property
    def enabled(self) -> bool:
        self.warn(stacklevel=3)
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
            self.warn(stacklevel=3)
            raise FeatureNotEnabledError(
                f"Usage requires {self._name}.enabled = {state}"
            )

    def warn(self, *, stacklevel: int = 2) -> None:
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
                stacklevel=stacklevel,
            )


server_kw_only = _Feature(
    "server_kw_only",
    """Optional arguments to Fido2Server, register_begin, and authenticate_begin will
be keyword-only in python-fido2 3.0, except authenticate_begin's credentials.
Required rp and user arguments remain positional-compatible. Keyword calls need
no opt-in. Set enabled to True to reject deprecated positional arguments now,
or False to retain them without warnings.""",
)


def _deprecated_positional_args(
    feature: _Feature, *names: str
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    def decorate(func: Callable[P, R]) -> Callable[P, R]:
        qualname = getattr(func, "__qualname__", type(func).__qualname__)
        positional_count = sum(
            p.kind in (Parameter.POSITIONAL_ONLY, Parameter.POSITIONAL_OR_KEYWORD)
            for p in signature(func).parameters.values()
        )

        @wraps(func)
        def wrapped(*args: Any, **kwargs: Any) -> R:
            extra_args = args[positional_count:]
            if extra_args:
                if len(extra_args) > len(names):
                    raise TypeError(
                        f"{qualname}() received too many positional arguments"
                    )
                for name, value in zip(names, extra_args):
                    if name in kwargs:
                        raise TypeError(
                            f"{qualname}() got multiple values for argument '{name}'"
                        )
                    kwargs[name] = value
                if feature._enabled is True:
                    raise TypeError(
                        f"{qualname}() optional arguments must be passed by keyword"
                    )
                feature.warn(stacklevel=3)
            return func(*args[:positional_count], **kwargs)

        return wrapped

    return decorate
