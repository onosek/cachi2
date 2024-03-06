import logging

import yaml

from cachi2.core.errors import PackageRejected
from cachi2.core.models.input import Request
from cachi2.core.models.output import EnvironmentVariable, RequestOutput
from cachi2.core.models.sbom import Component
from cachi2.core.package_managers.rpm.redhat.main import RedhatRpmsLock

log = logging.getLogger(__name__)


DEFAULT_LOCKFILE_NAME = "rpms.lock.yaml"


class LockfileFormat:
    def __init__(self, raw_content):
        self._handlers = []
        self._raw_content = raw_content
        self._matched_handler = None

    def get_matched_handler(self):
        return self._matched_handler

    def add_handler(self, handler) -> None:
        self._handlers.append(handler(self._raw_content))

    def process_formats(self) -> None:
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
            lockfile_format_processor.get_matched_handler().download(request.output_dir)

    return RequestOutput.from_obj_list(
        components, _generate_environment_variables(), project_files=[]
    )


def _check_lockfile(request: Request) -> None:
    if not request.source_dir.join_within_root(DEFAULT_LOCKFILE_NAME).path.exists():
        raise PackageRejected(
            f"Rpm lockfile '{DEFAULT_LOCKFILE_NAME}' missing, refusing to continue",
            solution=(
                "Make sure your repository has a rpm lockfile (e.g. rpms.lock.yaml) checked in "
                "to the repository"
            ),
        )


def _generate_environment_variables() -> list[EnvironmentVariable]:
    """Generate environment variables that will be used for building the project."""
    # TODO: set any environment values?
    env_vars = {"ENV_1": {"value": "?", "kind": "path"}, }

    return [EnvironmentVariable(name=name, **obj) for name, obj in env_vars.items()]
