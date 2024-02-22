# import hashlib
import logging
import os
import shlex
import shutil
import subprocess
import sys
from urllib.parse import urlparse

import requests
import yaml
from colorama import Fore, Style

from cachi2.core.errors import PackageRejected
from cachi2.core.models.input import Request
from cachi2.core.models.output import EnvironmentVariable, RequestOutput

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

    # h = hashlib.sha1(usedforsecurity=False)
    # with open("rpms.yaml", "rb") as f:
    #    for chunk in iter(lambda: f.read(4096), b""):
    #        h.update(chunk)
    # digest = h.hexdigest()

    for arch_data in config["arches"]:
        print("=== arch: ", arch_data["arch"])
        repo_dir = request.output_dir.join_within_root(arch_data["arch"])
        print(f"Downloading to {repo_dir}", file=sys.stderr)
        mount_dir = "/etc/yum.repos.d/repos"
        repoids = {}
        for package in arch_data.get("packages", {}):
            print("=== package:", package)
            repoids.setdefault(package["repoid"], []).append(package["url"])
            # TODO: use checksums & sizes as well
        print("=== repoids: ", repoids)

        repos = {}
        session = requests.Session()

        for repoid, urls in repoids.items():
            localpath = download_packages(session, repo_dir, repoid, urls)
            createrepo(repoid, localpath)
            repos[repoid] = os.path.join(mount_dir, os.path.relpath(localpath, repo_dir))

        repoids = {}
        for source in arch_data.get("sources", {}):
            print("=== source:", source)
            repoids.setdefault(source["repoid"], []).append(source["url"])
            # TODO: use checksums & sizes as well
        print("=== repoids: ", repoids)

        for repoid, urls in repoids.items():
            download_packages(session, repo_dir, repoid, urls)

        write_repofile(repo_dir, repos)

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


def download_file(session, dest_dir, url):
    filename = os.path.basename(urlparse(url).path)
    dest_file = os.path.join(dest_dir, filename)
    if os.path.exists(dest_file):
        return
    with session.get(url, stream=True) as r:
        if r.status_code == 404:
            raise RuntimeError(f"Not found: {url}")
        print(f"GET {Fore.BLUE}{url}{Style.RESET_ALL}", file=sys.stderr)
        with open(dest_file, "wb") as f:
            shutil.copyfileobj(r.raw, f)


def download_packages(session, dest_dir, repoid, urls):
    print(
        f"{Fore.GREEN}# Downloading packages for {repoid}{Style.RESET_ALL}",
        file=sys.stderr,
    )
    repodir = os.path.join(dest_dir, repoid)
    os.makedirs(repodir, exist_ok=True)
    for url in urls:
        download_file(session, repodir, url)
    return repodir


def createrepo(repoid, repodir):
    print(f"{Fore.GREEN}# Creating repo for {repoid}{Style.RESET_ALL}", file=sys.stderr)
    cmd = ["/usr/bin/createrepo", repodir]
    print("$ " + shlex.join(cmd), file=sys.stderr)
    print(Style.DIM, end="", flush=True, file=sys.stderr)
    subprocess.run(cmd, check=True)
    print(Style.RESET_ALL, end="", flush=True, file=sys.stderr)


def write_repofile(config_dir, repos):
    print(f"{Fore.GREEN}# Preparing repofile{Style.RESET_ALL}", file=sys.stderr)
    os.makedirs(config_dir, exist_ok=True)
    with open(os.path.join(config_dir, "custom.repo"), "w") as f:
        for repoid, path in sorted(repos.items()):
            print(f"[{repoid}]", file=f)
            print(f"baseurl = file://{path}", file=f)
