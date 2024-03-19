import logging
import os
import shlex
import subprocess
from pathlib import Path
from urllib.parse import quote

import rpmfile
import yaml

from cachi2.core.errors import PackageRejected
from cachi2.core.models.input import Request
from cachi2.core.models.output import EnvironmentVariable, ProjectFile, RequestOutput
from cachi2.core.models.sbom import Component
from cachi2.core.package_managers.rpm.redhat.main import RedhatRpmsLock
from cachi2.core.rooted_path import RootedPath
from cachi2.core.utils import run_cmd

log = logging.getLogger(__name__)


DEFAULT_LOCKFILE_NAME = "rpms.lock.yaml"
DEFAULT_PACKAGE_DIR = "deps/rpm"


class LockfileFormat:
    def __init__(self, raw_content):
        self._handlers = []
        self._raw_content = raw_content
        self._matched_handler = None

    def get_matched_handler(self):
        return self._matched_handler

    def add_handler(self, handler) -> None:
        self._handlers.append(handler(self._raw_content))

    def process_formats(self) -> bool:
        for handler in self._handlers:
            log.debug("Checking format '{}'".format(handler.__class__.__name__))
            if handler.match_format():
                log.debug("Lockfile content validation")
                handler.process_format()
                if handler.is_valid():
                    self._matched_handler = handler
                    return True

        raise PackageRejected(
            f"Rpm lockfile '{DEFAULT_LOCKFILE_NAME}' format is not supported'.",
            solution=("Check 'lockfileVendor' and 'lockfileVersion' keys in the lockfile."),
        )


def fetch_rpm_source(request: Request) -> RequestOutput:
    """Process all the yarn source directories in a request."""
    components: list[Component] = []

    _check_lockfile(request)
    lockfile_name = request.source_dir.join_within_root(DEFAULT_LOCKFILE_NAME)
    log.debug(f"Lockfile name given: {lockfile_name}")

    with open(lockfile_name) as f:
        raw_content = yaml.safe_load(f)

        # Create a list of format handlers and add handler for every supported format
        lockfile_format_processor = LockfileFormat(raw_content)
        lockfile_format_processor.add_handler(RedhatRpmsLock)
        if lockfile_format_processor.process_formats():
            package_dir = request.output_dir.join_within_root(DEFAULT_PACKAGE_DIR)
            handler = lockfile_format_processor.get_matched_handler()
            handler.download(package_dir)
            handler.verify_downloaded()
            files_metadata = handler.get_metadata()
            _generate_sbom_components(components, files_metadata)

    return RequestOutput.from_obj_list(
        components=components,
        environment_variables=_generate_environment_variables(DEFAULT_PACKAGE_DIR),
        project_files=_generate_repofiles(request.output_dir),
    )


def _generate_sbom_components(components: list[Component], files_metadata: dict) -> None:
    """ """
    for file_path, file_metadata in files_metadata.items():
        # iterate only through package metadata (skip sources metadata)
        if not file_metadata["package"]:
            continue
        # get (optional) 'epoch' - can't get it via rpmfile.headers
        rpm_args = [
            "-q",
            "--queryformat",
            "%|EPOCH?{%{EPOCH}}:{}|",  # return "" when epoch is not set instead of "(None)"
            file_path,
        ]
        epoch = run_cmd(cmd=["rpm", *rpm_args], params={})

        rpm_args = [
            "-q",
            "--queryformat",
            "%{LICENSE}",
            file_path,
        ]
        license = run_cmd(cmd=["rpm", *rpm_args], params={})

        with rpmfile.open(file_path) as rpm:
            vendor = rpm.headers.get("vendor", b"").decode()
            vendor = quote(vendor.lower())

            name = rpm.headers.get("name", b"").decode()
            version = rpm.headers.get("version", b"").decode()
            release = rpm.headers.get("release", b"").decode()
            arch = rpm.headers.get("arch", b"").decode()
            download_url = quote(file_metadata["url"])

            # https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#rpm
            # https://github.com/package-url/purl-spec/blob/master/PURL-SPECIFICATION.rst#known-qualifiers-keyvalue-pairsa
            purl = (
                f"pkg:rpm{'/' if vendor else ''}{vendor}/{name}@{version}{release}"
                f"?arch={arch}{'&epoch=' if epoch else ''}{epoch}&download_url={download_url}"
            )

            components.append(
                Component(
                    name=name,
                    version=version,
                    purl=purl,
                    # NOTE: add checksum?
                )
            )


def process_packages(path: Path) -> None:
    """ """
    # search structure for all repoid dirs and create repository metadata
    # out of its RPMs. Skip sources dir that contains only SRPMs.
    package_dir = RootedPath(path).join_within_root(DEFAULT_PACKAGE_DIR)
    for subdir in os.listdir(package_dir):
        if subdir == "sources":
            continue
        arch = subdir
        for repoid in os.listdir(os.path.join(package_dir, arch)):
            localpath = os.path.join(package_dir, arch, repoid)
            createrepo(repoid, localpath)


def createrepo(repoid: str, repodir: str) -> None:
    """ """
    log.info(f"Creating repository metadata for repoid '{repoid}': {repodir}")
    cmd = ["/usr/bin/createrepo", repodir]
    log.debug("$ " + shlex.join(cmd))
    subprocess.run(cmd, check=True)


def _generate_repofiles(path: Path) -> list[ProjectFile]:
    """ """
    # search structure and generate repofile for each arch in its dir.
    # Repofile contains all arch's repoids. Skip sources dir that contains only SRPMs.
    project_files = []
    package_dir = RootedPath(path).join_within_root(DEFAULT_PACKAGE_DIR)
    for subdir in os.listdir(package_dir):
        if subdir == "sources":
            continue
        arch = subdir
        log.debug(f"Preparing repofile for arch '{arch}'")
        abspath = os.path.join(package_dir, arch, "cachi2.repo")
        template = ""
        for repoid in os.listdir(os.path.join(package_dir, arch)):
            localpath = os.path.join(package_dir, arch, repoid)
            template += f"[{repoid}]\n"
            template += f"baseurl = file://{localpath}\n"
        project_files.append({"abspath": abspath, "template": template})
    return project_files


def _check_lockfile(request: Request) -> None:
    if not request.source_dir.join_within_root(DEFAULT_LOCKFILE_NAME).path.exists():
        raise PackageRejected(
            f"Rpm lockfile '{DEFAULT_LOCKFILE_NAME}' missing, refusing to continue",
            solution=(
                "Make sure your repository has a rpm lockfile (e.g. rpms.lock.yaml) checked in "
                "to the repository"
            ),
        )


def _generate_environment_variables(package_dir: str) -> list[EnvironmentVariable]:
    """Generate environment variables that will be used for building the project."""

    env_vars = {
        # "PACKAGE_DIR": {"value": package_dir, "kind": "path"},  # TODO: do I need it?
        # "USE_PACKAGE_MANAGER": {"value": "rpm", "kind": "literal"},
    }

    return [EnvironmentVariable(name=name, **obj) for name, obj in env_vars.items()]
