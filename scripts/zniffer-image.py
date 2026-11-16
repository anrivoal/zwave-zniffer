#!/usr/bin/env python3
"""Build the local Zniffer Docker image or create and publish a Git release tag."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IMAGE_NAME = "zw-zniffer"
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
DOCKER_TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")


class Colors:
    enabled = sys.stdout.isatty() and os.environ.get("TERM") != "dumb"
    CYAN = "\033[36m" if enabled else ""
    GREEN = "\033[32m" if enabled else ""
    RED = "\033[31m" if enabled else ""
    YELLOW = "\033[33m" if enabled else ""
    NC = "\033[0m" if enabled else ""


def log(message: str, status: str = "info") -> None:
    icons = {
        "info": f"{Colors.CYAN}➤{Colors.NC}",
        "ok": f"{Colors.GREEN}✓{Colors.NC}",
        "fail": f"{Colors.RED}✗{Colors.NC}",
        "warn": f"{Colors.YELLOW}⚠{Colors.NC}",
    }
    print(f"  {icons[status]} {message}", flush=True)


def run_with_spinner(
    cmd: list[str], section: str, *, cwd: Path = ROOT
) -> tuple[bool, str]:
    """Run a command with a terminal spinner and show captured output on failure."""
    chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    stop_spinner = threading.Event()
    use_spinner = sys.stdout.isatty()

    def spin() -> None:
        while not stop_spinner.is_set():
            char = chars[int(time.time() * 10) % len(chars)]
            print(f"\r  {Colors.CYAN}{char}{Colors.NC} {section}  ", end="", flush=True)
            stop_spinner.wait(0.1)

    if not use_spinner:
        log(section)

    try:
        process = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        thread = threading.Thread(target=spin, daemon=True) if use_spinner else None
        if thread:
            thread.start()
        output, _ = process.communicate()
        stop_spinner.set()
        if thread:
            thread.join()

        if process.returncode == 0:
            if use_spinner:
                print(f"\r  {Colors.GREEN}✓{Colors.NC} {section}                    ", flush=True)
            else:
                log(section, "ok")
            return True, output

        if use_spinner:
            print(f"\r  {Colors.RED}✗{Colors.NC} {section} (exit {process.returncode})", flush=True)
        else:
            log(f"{section} (exit {process.returncode})", "fail")
        if output:
            print("\n".join(f"    {line}" for line in output.rstrip().splitlines()), flush=True)
        return False, output
    except OSError as exc:
        stop_spinner.set()
        log(f"{section}: {exc}", "fail")
        return False, str(exc)


def git_output(*args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def current_image_version() -> str:
    version = git_output("describe", "--tags", "--always", "--dirty")
    if git_output("status", "--porcelain") and not version.endswith("-dirty"):
        version += "-dirty"
    if not DOCKER_TAG.fullmatch(version):
        raise RuntimeError(f"Git describe returned an invalid Docker tag: {version}")
    return version


def docker_ready() -> bool:
    if not shutil.which("docker"):
        log("Docker CLI is not installed or is missing from PATH", "fail")
        return False
    ok, _ = run_with_spinner(["docker", "info"], "Check local Docker daemon")
    return ok


def build_image(version: str) -> bool:
    image = f"{IMAGE_NAME}:{version}"
    ok, _ = run_with_spinner(
        [
            "docker",
            "build",
            "--progress=plain",
            "--build-arg",
            f"APP_VERSION={version}",
            "--file",
            "Dockerfile.zniffer",
            "--tag",
            image,
            ".",
        ],
        f"Build local image {image}",
    )
    if ok:
        log(f"Image ready in the local Docker daemon: {image}", "ok")
        log("Run it with: docker run --rm -p 127.0.0.1:8080:8080 " + image)
    return ok


def build_current() -> bool:
    try:
        version = current_image_version()
    except (subprocess.CalledProcessError, RuntimeError) as exc:
        log(f"Could not determine version with git describe: {exc}", "fail")
        return False
    log(f"Image version from git describe: {version}")
    return build_image(version)


def suggested_release_version() -> str:
    tags = git_output("tag", "--list").splitlines()
    versions = [tuple(map(int, match.groups())) for tag in tags if (match := SEMVER.fullmatch(tag))]
    if not versions:
        return "0.0.1"
    major, minor, patch = max(versions)
    return f"{major}.{minor}.{patch + 1}"


def choose_remote() -> str | None:
    remotes = git_output("remote").splitlines()
    if not remotes:
        log("No Git remote is configured; add one before releasing", "fail")
        return None
    if "origin" in remotes:
        return "origin"
    if len(remotes) == 1:
        return remotes[0]
    print("\n  Git remotes:", flush=True)
    for index, remote in enumerate(remotes, 1):
        print(f"    {index}. {remote}", flush=True)
    try:
        selected = input("  Push release tag to remote [1]: ").strip() or "1"
        return remotes[int(selected) - 1]
    except (ValueError, IndexError, EOFError):
        log("Invalid remote selection", "fail")
        return None


def release() -> bool:
    try:
        if git_output("status", "--porcelain"):
            log("Release requires a clean Git worktree. Commit or stash changes first.", "fail")
            return False
        remote = choose_remote()
        if not remote:
            return False
        if not docker_ready():
            return False

        default_version = suggested_release_version()
        version = input(f"\n  Release version [{default_version}]: ").strip() or default_version
        if not SEMVER.fullmatch(version):
            log("Release version must use plain semantic versioning, for example 0.0.1", "fail")
            return False

        head = git_output("rev-parse", "HEAD")
        existing = subprocess.run(
            ["git", "rev-parse", "--verify", f"refs/tags/{version}^{{}}"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        if existing.returncode == 0 and existing.stdout.strip() != head:
            log(f"Tag {version} already exists on a different commit", "fail")
            return False

        print("\n  Release plan", flush=True)
        print(f"    Git tag:       {version} → {head[:12]}", flush=True)
        print(f"    Local image:   {IMAGE_NAME}:{version}", flush=True)
        print(f"    Push Git tag:  {remote}", flush=True)
        print("    Docker image will stay in the local daemon.", flush=True)
        if input("\n  Continue? [y/N]: ").strip().lower() not in {"y", "yes"}:
            log("Release cancelled", "warn")
            return False

        if existing.returncode != 0:
            ok, _ = run_with_spinner(
                ["git", "tag", "--annotate", version, "--message", f"Release {version}", head],
                f"Create Git tag {version}",
            )
            if not ok:
                return False
        else:
            log(f"Tag {version} already exists on this commit; continuing", "warn")

        tagged_version = git_output(
            "describe", "--tags", "--exact-match", f"--match={version}", "HEAD"
        )
        if not build_image(tagged_version):
            log(f"Tag {version} remains local; rerun release after fixing the build", "warn")
            return False

        ok, _ = run_with_spinner(
            ["git", "push", remote, f"refs/tags/{version}"],
            f"Push Git tag {version} to {remote}",
        )
        if not ok:
            log(f"Local tag and image remain available; push {version} to {remote} when ready", "warn")
            return False

        log(f"Release {version} complete", "ok")
        return True
    except (subprocess.CalledProcessError, RuntimeError, EOFError) as exc:
        log(f"Release failed: {exc}", "fail")
        return False


def main() -> int:
    print("\n  Z-Wave Zniffer image builder", flush=True)
    print("  ───────────────────────────", flush=True)
    if len(sys.argv) > 1:
        action = sys.argv[1].lower()
        if action == "build":
            return 0 if docker_ready() and build_current() else 1
        if action == "release":
            return 0 if release() else 1
        print(f"Usage: {Path(sys.argv[0]).name} [build|release]", file=sys.stderr)
        return 2

    print("\n    1. Build image from the current Git version", flush=True)
    print("    2. Release: create tag, build image, push tag", flush=True)
    print("    0. Exit", flush=True)
    try:
        choice = input("\n  Select an action [1]: ").strip() or "1"
    except EOFError:
        return 2
    if choice == "1":
        return 0 if docker_ready() and build_current() else 1
    if choice == "2":
        return 0 if release() else 1
    if choice == "0":
        return 0
    log("Unknown action", "fail")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
