from typing import Optional

from teapot.arch.architecture import Architecture


class ArchSpecificPassMixin:
    EXPECTED_ARCH: Optional[str] = None

    def check_expected_arch(self, arch: Architecture) -> None:
        if self.EXPECTED_ARCH is not None and arch.name != self.EXPECTED_ARCH:
            raise ValueError(f"{self.__class__.__name__} cannot run on {arch.name}")
