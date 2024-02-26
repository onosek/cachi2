# import hashlib
import logging

import yaml

from cachi2.core.errors import PackageRejected
from cachi2.core.models.input import Request
from cachi2.core.models.output import EnvironmentVariable, RequestOutput
from cachi2.core.package_managers.rpm.redhat.main import process_redhat_lockfile

log = logging.getLogger(__name__)


DEFAULT_LOCKFILE_NAME = "rpms.lock.yaml"


def fetch_rpm_source(request: Request) -> RequestOutput:
    """Process all the yarn source directories in a request."""
    components = []

    _check_lockfile(request)
    lockfile_name = request.source_dir.join_within_root(DEFAULT_LOCKFILE_NAME)
    print("=== lockfile_name:", lockfile_name)
    with open(lockfile_name) as f:
        config = yaml.safe_load(f)

        vendor = config.get("lockfileVendor")
        if vendor is None:
            raise PackageRejected(
                f"Rpm lockfile '{DEFAULT_LOCKFILE_NAME}' doesn't contain a key 'lockfileVendor' "
                "or this key is empty.",
                solution=("Set 'lockfileVendor' key in the lockfile."),
            )

        if vendor == "redhat":
            process_redhat_lockfile(request, config)
        else:
            raise PackageRejected(
                f"Rpm lockfile '{DEFAULT_LOCKFILE_NAME}' contains a data of vendor '{vendor}'. "
                "A parser for that hasn't been implemented yet",
                solution=("Use the proper vendor format of the lockfile."),
            )

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
    env_vars = {}

    return [EnvironmentVariable(name=name, **obj) for name, obj in env_vars.items()]
