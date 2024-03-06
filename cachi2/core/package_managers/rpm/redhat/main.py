import asyncio
import logging
import os
from typing import Optional

from pydantic import BaseModel, PositiveInt, ValidationError, validator

from cachi2.core.config import get_config
from cachi2.core.package_managers.general import async_download_files
from cachi2.core.package_managers.rpm.base import RpmsLock
from cachi2.core.rooted_path import RootedPath

log = logging.getLogger(__name__)


class Package(BaseModel):
    repoid: str
    url: str
    checksum: Optional[str] = None
    size: Optional[int] = None


class Arch(BaseModel):
    arch: str
    packages: Optional[list[Package]] = []
    sources: Optional[list[Package]] = []

    @validator("sources", "packages")
    def validate_version(cls, v):
        if v is None:
            return []  # set default value
        return v


class Root(BaseModel):
    lockfileVersion: PositiveInt
    lockfileVendor: str
    arches: list[Arch]


#    @validator("lockfileVersion", pre=True)
#    def validate_version(cls, v):
#        if v != 1:
#            raise ValueError("Unsupported lockfile version.")
#        return v

#    @validator("lockfileVendor", pre=True)
#    def validate_vendor(cls, v):
#        if v != "redhat":
#            raise ValueError("Unsupported vendor.")
#        return v


# just a minimal set of fields to identify the format
class Header(BaseModel):
    lockfileVersion: PositiveInt
    lockfileVendor: str


class RedhatRpmsLock(RpmsLock):
    def match_format(self) -> bool:
        try:
            header = Header(**self._content)
        except ValidationError:
            return False
        return header.lockfileVendor == "redhat" and header.lockfileVersion == 1

    def process_format(self) -> None:
        self._lockfile = Root(**self._content)

    def download(self, output_dir: RootedPath) -> None:
        for arch in self._lockfile.arches:
            files = {}
            files_sbom = {}
            for pkg in arch.packages:
                dest = output_dir.join_within_root(arch.arch, pkg.repoid, os.path.basename(pkg.url))
                files[pkg.url] = dest.path
                files_sbom[dest.path] = pkg.url
                os.makedirs(os.path.dirname(dest.path), exist_ok=True)

            for pkg in arch.sources:
                dest = output_dir.join_within_root(
                    "sources", arch.arch, pkg.repoid, os.path.basename(pkg.url)
                )
                files[pkg.url] = dest.path
                os.makedirs(os.path.dirname(dest.path), exist_ok=True)

            asyncio.run(async_download_files(files, get_config().concurrency_limit))
            self._files_sbom.update(files_sbom)
            self.verify_downloaded()

    def verify_downloaded(self) -> None:
        # TODO: use checksums & sizes as well
        pass
