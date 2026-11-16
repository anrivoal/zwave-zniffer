#!/usr/bin/env python3
"""Prepare the workspace and start its web service when the container starts."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
BUILD_DIR = ROOT / "build"
PID_FILE = Path("/tmp/zniffer_service.pid")
LOG_FILE = Path("/tmp/zniffer_service.log")


class Colors:
    enabled = sys.stdout.isatty() and os.environ.get("TERM") != "dumb"
    CYAN = "\033[36m" if enabled else ""
    GREEN = "\033[32m" if enabled else ""
    RED = "\033[31m" if enabled else ""
    YELLOW = "\033[33m" if enabled else ""
    ORANGE = "\033[38;5;208m" if enabled else ""
    NC = "\033[0m" if enabled else ""


def log(message: str, status: str = "info", indent: bool = True) -> None:
    icons = {
        "info": f"{Colors.CYAN}➤{Colors.NC}",
        "ok": f"{Colors.GREEN}✓{Colors.NC}",
        "fail": f"{Colors.RED}✗{Colors.NC}",
        "warn": f"{Colors.YELLOW}⚠{Colors.NC}",
        "skip": f"{Colors.ORANGE}⊘{Colors.NC}",
    }
    prefix = "  " if indent else ""
    print(f"{prefix}{icons[status]} {message}", flush=True)


def run_with_spinner(
    cmd: list[str], cwd: Path | None = None, section: str = "Processing"
) -> bool:
    """Run a command with a spinner; print its output if it fails."""
    chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    stop_spinner = threading.Event()
    output = ""
    use_spinner = sys.stdout.isatty()

    def spin() -> None:
        while not stop_spinner.is_set():
            char = chars[int(time.time() * 10) % len(chars)]
            print(f"\r  {Colors.CYAN}{char}{Colors.NC} {section}  ", end="", flush=True)
            stop_spinner.wait(0.1)

    try:
        if not use_spinner:
            log(section)
        process = subprocess.Popen(
            cmd,
            cwd=cwd or ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        thread = None
        if use_spinner:
            thread = threading.Thread(target=spin, daemon=True)
            thread.start()
        assert process.stdout is not None
        output, _ = process.communicate()
        stop_spinner.set()
        if thread is not None:
            thread.join()

        if process.returncode == 0:
            if use_spinner:
                print(f"\r  {Colors.GREEN}✓{Colors.NC} {section}                    ", flush=True)
            else:
                log(section, "ok")
            return True

        if use_spinner:
            print(f"\r  {Colors.RED}✗{Colors.NC} {section} (exit {process.returncode})", flush=True)
        else:
            log(f"{section} (exit {process.returncode})", "fail")
        if output:
            print("\n".join(f"    {line}" for line in output.rstrip().splitlines()), flush=True)
        return False
    except Exception as exc:
        stop_spinner.set()
        if use_spinner:
            print(f"\r  {Colors.RED}✗{Colors.NC} {section}: {exc}", flush=True)
        else:
            log(f"{section}: {exc}", "fail")
        return False


def pid_is_running() -> bool:
    try:
        pid = int(PID_FILE.read_text().strip())
        os.kill(pid, 0)
        command = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ")
        return str(BUILD_DIR / "zniffer_service").encode() in command
    except (OSError, ValueError):
        PID_FILE.unlink(missing_ok=True)
        return False


def port_is_open() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 8080), timeout=0.5):
            return True
    except OSError:
        return False


def show_service_log() -> None:
    if not LOG_FILE.exists():
        return
    lines = LOG_FILE.read_text(errors="replace").splitlines()[-30:]
    if lines:
        log("Last service log lines:", "warn")
        for line in lines:
            print(f"    {line}", flush=True)


def prepare_workspace() -> bool:
    venv_python = ROOT / ".venv" / "bin" / "python"
    if not venv_python.is_file():
        if not run_with_spinner(
            ["python3", "-m", "venv", "--copies", ".venv"], section="Create Python environment"
        ):
            return False
    else:
        log("Python environment is ready", "skip")

    codex = Path("/home/zwave/.local/bin/codex")
    if not codex.exists():
        if not run_with_spinner(
            ["npm", "install", "--global", "--prefix", "/home/zwave/.local", "@openai/codex@latest"],
            section="Install Codex",
        ):
            return False
    else:
        log("Codex is installed", "skip")

    if not run_with_spinner(["cmake", "-S", ".", "-B", "build"], section="Configure CMake"):
        return False
    return run_with_spinner(
        ["cmake", "--build", "build", "--target", "zniffer_service", "-j2"],
        section="Build Zniffer service",
    )


def start_service() -> bool:
    if pid_is_running():
        if port_is_open():
            log("Zniffer service is already listening on port 8080", "skip")
            return True
        log("Service process exists but port 8080 is not accepting connections", "warn")

    executable = BUILD_DIR / "zniffer_service"
    if not executable.is_file():
        log("Zniffer service executable is missing", "fail")
        return False

    try:
        log("Start Zniffer web service")
        LOG_FILE.write_text("")
        with LOG_FILE.open("a") as log_file:
            process = subprocess.Popen(
                [str(executable)],
                cwd=ROOT,
                env={
                    **os.environ,
                    "ZW_PORT": "8080",
                    "ZW_WEB_ROOT": "web",
                    "ZW_XML_ROOT": "assets/xml",
                },
                stdin=subprocess.DEVNULL,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        PID_FILE.write_text(f"{process.pid}\n")
        for _ in range(50):
            if process.poll() is not None:
                log(f"Service exited with status {process.returncode}", "fail")
                PID_FILE.unlink(missing_ok=True)
                show_service_log()
                return False
            if port_is_open():
                break
            time.sleep(0.1)
        else:
            log("Service is running but port 8080 did not open", "fail")
            show_service_log()
            return False
        log("Zniffer web service is running on port 8080", "ok")
        log("URL: http://localhost:8080", "info")
        return True
    except OSError as exc:
        log(f"Could not start Zniffer service: {exc}", "fail")
        return False


def main() -> int:
    print("\n  zw-py-tools container startup", flush=True)
    print("  ────────────────────────────", flush=True)
    if not prepare_workspace() or not start_service():
        log("Startup did not complete", "fail", indent=False)
        return 1
    log("Startup complete", "ok", indent=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
