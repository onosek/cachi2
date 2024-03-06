from typing import Any

from cachi2.core.rooted_path import RootedPath


class RpmsLock:
    def __init__(self, content: dict[str, Any]):
        self._content = content
        self._lockfile = None
        self._files_sbom = {}

    def is_valid(self) -> bool:
        return self._lockfile is not None and self._lockfile

    def match_format(self) -> bool:
        raise NotImplementedError

    def process_format(self) -> bool:
        raise NotImplementedError

    def download(self, output_dir: RootedPath):
        raise NotImplementedError
