from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from androguard.core.analysis.analysis import Analysis
from androguard.core.apk import APK


@dataclass
class APKAttributes:
    _a: Optional[APK] = None
    _dx: Optional[Analysis] = None
    _d: list = None
    input_path: Optional[Path] = None
    output_path: Optional[Path] = None
    package_name: str = None


class LoadedAPK:
    def __init__(self):
        self._attrs = APKAttributes()

    @property
    def _a(self):
        return self._attrs._a

    @_a.setter
    def _a(self, value):
        self._attrs._a = value

    @property
    def _dx(self):
        return self._attrs._dx

    @_dx.setter
    def _dx(self, value):
        self._attrs._dx = value

    @property
    def _d(self):
        return self._attrs._d

    @_d.setter
    def _d(self, value):
        self._attrs._d = value

    @property
    def _input_path(self):
        return self._attrs.input_path

    @_input_path.setter
    def _input_path(self, value):
        self._attrs._input_path = value

    @property
    def output_path(self):
        return self._attrs.output_path

    @output_path.setter
    def output_path(self, value):
        self._attrs._output_path = value

    @property
    def package_name(self):
        return self._attrs.package_name

    @package_name.setter
    def package_name(self, value):
        self._attrs.package_name = value
