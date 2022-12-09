# __main__.py

import os
import argparse
import textwrap
import pytest
import sysconfig
import subprocess

# from posixath import feed, viewer
"""
python -m posixath --linux -t T1058
"""

MODULE_NAME = "posixath"


def get_args() -> tuple[argparse.Namespace, list[str]]:
    description = textwrap.dedent(
        """
    PosixATH is the POSIX version of AtomicTestHarness that provides support for
    macOS and Linux operating systems. AtomicTestHarnesses streamlines the
    execution of ATT&CK technique variations and validates that the expected
    telemetry surfaces in the process.
    """
    )
    epilog = textwrap.dedent(
        """
    Examples:

    Run all of the variations of ATT&CK technique T1018 for Linux
        python -m posixath linux -t T1018

    Run all of the variations of ATT&CK technique T1059.002 for macOS
        python -m posixath macos -t T1059_002
    """
    )
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description=description,
        prog="PosixATH",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    parser.add_argument(
        "platform",
        type=str,
        choices=["linux", "macos"],
        help="The target platform to test",
    )
    parser.add_argument(
        "-l",
        "--list",
        action="store_true",
        help="Lists the available tests based on the scope specified in the command line",
    )
    parser.add_argument(
        "-t", "--technique-id", type=str, help="The technique id to test"
    )
    parser.add_argument(
        "-k",
        dest="subtest",
        type=str,
        help="A string of keywords that specify which set of tests to run",
    )
    return parser.parse_known_args()


def main():
    """
    Run the program.
    """

    args, other = get_args()
    package_path = os.path.join(sysconfig.get_paths()["purelib"], MODULE_NAME)
    pytest_args: list[str] = [
        package_path,
        "-m",
        args.platform,
        "-v",
        "-s",
    ]

    if args.technique_id is not None:
        pytest_args.extend(["-k", args.technique_id])

    if args.subtest is not None:
        pytest_args.extend(["-k", args.subtest])

    if args.list:
        new_args = ["pytest", package_path, *pytest_args[1:]]
        new_args.append("--co")
        ret = subprocess.run(new_args, capture_output=True)
        try:
            # Skip the header lines
            data = ret.stdout.split(b"\n")[6:]
            for item in data:
                item = item.decode().strip().strip("<>")

                if "Module" in item:
                    print(
                        f"Attack id: {item.replace('Module test_', '').replace('.py', '')}"
                    )
                if "Class" in item:
                    print(f"  Group: {item.replace('Class ', '')}")
                if "Function" in item:
                    test_name = item.replace("Function test_", "")
                    print(f"    {test_name}")
        except:
            print("And error occurred while getting the vailable tests")
    else:
        if other:
            pytest_args.extend(other)

        pytest.main(pytest_args)


if __name__ == "__main__":
    main()
