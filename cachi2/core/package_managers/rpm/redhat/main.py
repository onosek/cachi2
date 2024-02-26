# import hashlib
import jsonschema
import logging
import os
import shlex
import shutil
import subprocess
import sys
from urllib.parse import urlparse

import requests
from colorama import Fore, Style

from cachi2.core.models.input import Request

log = logging.getLogger(__name__)


# Example JSON Schema
yaml_schema = {
    "type": "object",
    "properties": {
        "lockfileVersion": {"type": "integer", "minimum": 0},
        "lockfileVendor": {"type": "string"},
    },
    "required": ["lockfileVersion", "lockfileVendor"]
}


def process_redhat_lockfile(request: Request, config: dict) -> None:
    """Process all the yarn source directories in a request."""

    # h = hashlib.sha1(usedforsecurity=False)
    # with open("rpms.yaml", "rb") as f:
    #    for chunk in iter(lambda: f.read(4096), b""):
    #        h.update(chunk)
    # digest = h.hexdigest()

    # Perform validation
    validate_yaml(config, yaml_schema)

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


def validate_yaml(yaml_data, schema):
    try:
        # Validate against JSON Schema
        jsonschema.validate(instance=yaml_data, schema=schema)

        print("Validation successful!")
    except jsonschema.ValidationError as e:
        print(f"Validation error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")


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
