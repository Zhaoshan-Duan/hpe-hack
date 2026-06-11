#!/usr/bin/env python3
"""
run_test.py - simulate the contest grader locally.

Usage:
    python3 run_test.py <test.json> <stor-binary> [options]

Options:
    --plant-db <enc.db>   copy this file into the temp dir as enc.db before
                          running commands (local testing only; not a grader
                          feature for crash/security/correctness tests)
    --docker <image>      run each command inside the named Docker image
                          (required when the binary needs 32-bit libs that are
                          only present inside the contest image, e.g. libsodium)
                          Example: --docker bibifi

The grader runs each command in sequence inside a single temp directory so
enc.db persists across commands (register -> create -> write -> exploit all
share one store).

Exit 0 = win condition triggered (would score against the target)
Exit 1 = no win condition (would not score)
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile

WIN_STRING = b"Arbitrary access achieved!"
TIMEOUT_SECS = 60


def signal_name(sig):
    try:
        return signal.Signals(sig).name
    except ValueError:
        return f"SIG{sig}"


def classify_exit(returncode):
    if returncode >= 0:
        return f"exit {returncode}"
    return f"killed by {signal_name(-returncode)} ({returncode})"


def build_docker_args(docker_image, stor_bin, tmpdir, cmd_args):
    """
    Wrap a stor invocation in 'docker run' so it executes inside the contest
    image (which has 32-bit libsodium etc.).  The tmpdir is bind-mounted to
    /work inside the container so enc.db persists across commands.
    The binary is bind-mounted to /stor inside the container.
    """
    stor_bin_abs = os.path.abspath(stor_bin)
    return [
        "docker", "run", "--rm",
        "-v", f"{tmpdir}:/work",
        "-v", f"{stor_bin_abs}:/stor",
        "-w", "/work",
        "--network", "none",
        docker_image,
        "/stor",
    ] + cmd_args


def run_test(test_path, stor_bin, plant_db=None, docker_image=None):
    stor_bin = os.path.abspath(stor_bin)

    with open(test_path) as f:
        data = json.load(f)

    test_type = data["type"]
    commands = data["commands"]

    print(f"target_team : {data.get('target_team', '?')}")
    print(f"type        : {test_type}")
    print(f"binary      : {stor_bin}")
    if docker_image:
        print(f"docker      : {docker_image}")
    print(f"commands    : {len(commands)}")
    print()

    with tempfile.TemporaryDirectory() as tmpdir:
        if plant_db:
            shutil.copy(plant_db, os.path.join(tmpdir, "enc.db"))
            print(f"[setup] planted {plant_db} as enc.db\n")

        for idx, cmd in enumerate(commands):
            if docker_image:
                args = build_docker_args(docker_image, stor_bin, tmpdir, cmd["args"])
            else:
                args = [stor_bin] + cmd["args"]
            stdin_bytes = cmd["stdin"].encode() if "stdin" in cmd else None

            print(f"[cmd {idx}] {' '.join(cmd['args'])}")
            if stdin_bytes is not None:
                preview = stdin_bytes[:64]
                suffix = b"..." if len(stdin_bytes) > 64 else b""
                print(f"  stdin   : {preview!r}{suffix.decode()}")

            try:
                result = subprocess.run(
                    args,
                    input=stdin_bytes,
                    capture_output=True,
                    timeout=TIMEOUT_SECS,
                    cwd=None if docker_image else tmpdir,
                )
            except subprocess.TimeoutExpired:
                print(f"  -> TIMEOUT (>{TIMEOUT_SECS}s)")
                if test_type == "crash":
                    print("\n[PASS] crash: DoS via timeout")
                    return True
                print(f"\n[FAIL] timeout but type={test_type!r}")
                return False

            stdout = result.stdout
            stderr = result.stderr
            rc = result.returncode

            print(f"  stdout  : {stdout!r}")
            if stderr:
                print(f"  stderr  : {stderr!r}")
            print(f"  status  : {classify_exit(rc)}")

            # "Arbitrary access achieved!" anywhere in stdout -> security win
            if WIN_STRING in stdout:
                print(f"\n[PASS] security: win() reached")
                return True

            # Signal handling.
            # Direct execution: rc < 0, value is -signum (Python convention).
            # Docker: process signal death appears as rc = 128 + signum.
            # Normalise to a signal number or None.
            sig = None
            if rc < 0:
                sig = -rc
            elif rc > 128:
                sig = rc - 128

            if sig is not None:
                name = signal_name(sig)
                if sig == signal.SIGSEGV:
                    print(f"  -> SIGSEGV")
                    if test_type == "crash":
                        print("\n[PASS] crash: SIGSEGV")
                        return True
                    print(f"\n[FAIL] SIGSEGV but type={test_type!r}")
                    return False
                elif sig == signal.SIGABRT:
                    # SIGABRT = assert / heap-abort (dlmalloc internal check).
                    # Counts as crash per contest rules.
                    print(f"  -> SIGABRT (heap corruption / assert)")
                    if test_type == "crash":
                        print("\n[PASS] crash: SIGABRT (heap abort)")
                        return True
                    print(f"\n[FAIL] SIGABRT but type={test_type!r}")
                    return False
                else:
                    print(f"  -> {name}: investigate")

            # Confidentiality: exact byte match — spec says read outputs
            # content verbatim with no added newline, so no strip().
            if "output" in cmd:
                expected = cmd["output"].encode()
                if stdout == expected:
                    print(f"\n[PASS] confidentiality: stdout matches claimed secret")
                    return True
                print(f"\n[FAIL] confidentiality: expected {expected!r}, got {stdout!r}")
                return False

        # Correctness: the grader compares output/exit against spec.
        # We report what we saw; human review required to confirm.
        if test_type == "correctness":
            print("\n[MANUAL] correctness: review output above against spec")
            return None

        print("\n[FAIL] no win condition triggered")
        return False


def main():
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} <test.json> <stor-binary> [--plant-db <enc.db>] [--docker <image>]")
        sys.exit(2)

    test_path = sys.argv[1]
    stor_bin = sys.argv[2]
    plant_db = None
    docker_image = None

    i = 3
    while i < len(sys.argv):
        if sys.argv[i] == "--plant-db" and i + 1 < len(sys.argv):
            plant_db = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "--docker" and i + 1 < len(sys.argv):
            docker_image = sys.argv[i + 1]
            i += 2
        else:
            print(f"unknown argument: {sys.argv[i]}", file=sys.stderr)
            sys.exit(2)

    result = run_test(test_path, stor_bin, plant_db, docker_image)
    sys.exit(0 if result else 1)


if __name__ == "__main__":
    main()
