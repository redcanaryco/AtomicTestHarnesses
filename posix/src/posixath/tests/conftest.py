import pytest
from pathlib import Path


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--shellcode-path",
        action="store",
        type=Path,
        default=None,
        help="The path to a file containing shellcode. This shellcode is to be injected into --target-proc",
    )
    parser.addoption(
        "--target-proc",
        action="store",
        type=Path,
        default=None,
        help="The full path to an executable. This executable is used as the target of the ptrace calls for the test",
    )
    parser.addoption(
        "--target-args",
        action="store",
        default=None,
        help="The command line arguments for --target-proc. Enter these as a single string of space separated values.",
    )
    parser.addoption(
        "--osascript-path",
        action="store",
        type=Path,
        default=None,
        help="The path to an uncompiled OSA (Open Scripting Architecture) script. E.g. AppleScript or JXA.",
    )
    parser.addoption(
        "--osa-shell-path",
        action="store",
        type=Path,
        default=None,
        help="The path to an OSA (Open Scripting Architecture) shell script. E.g. `#!/usr/bin/osascript`",
    )
