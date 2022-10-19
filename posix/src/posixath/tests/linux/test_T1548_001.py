"""
Set of tests for Attack Technique T1548.001 (setuid/setgid)
"""
import os
import stat
import rich
import pytest
import shutil

from pathlib import Path
from _pytest.fixtures import SubRequest
from ...utils.common import LinuxSTDLib as stdlib, StandardizedCompletedProcess


def is_suid(mode: int) -> bool:
    """
    Check if the set-uid bit is set.
    """
    return mode & stat.S_ISUID != 0


def is_sgid(mode: int) -> bool:
    """
    Check if the set-gid bit is set.
    """
    return mode & stat.S_ISGID != 0


# Run after all tests are run
def finalizer_function():
    """
    Make sure that `cat` is back at it's default permissions
    """
    full_path = shutil.which("cat")
    if full_path is None:
        pytest.skip("Failed to find system binary `cat`")

    full_path = Path(full_path)
    full_path.chmod(0o755)


# Run before all test run
@pytest.fixture(scope="session", autouse=True)
def run_before_tests(request: SubRequest):
    # prepare something ahead of all tests
    request.addfinalizer(finalizer_function)


@pytest.fixture
def bin_path():
    """
    Pytest fixture for helping with attack coverage.
    """
    # chmod using --reference=rfile
    new_file: Path = Path("myfile.txt")
    new_file.touch()
    new_file.chmod(0o6755)

    bin_path = shutil.which("cat")
    if bin_path is None:
        pytest.skip("Failed to find system binary `cat`")

    bin_path = Path(bin_path)
    mode = bin_path.stat().st_mode
    assert is_suid(mode) == False

    # Run the test
    yield bin_path

    # Put permissions back to where they were
    bin_path.chmod(mode)
    assert (
        bin_path.stat().st_mode == mode
    ), "Failed to return `cat` permissions back to normal"

    new_file.unlink()


@pytest.mark.linux
class TestSetUid:
    @pytest.mark.parametrize("args", ["4755", "u+s", "--reference=myfile.txt"])
    def test_chmod(self, args: str, bin_path: Path):
        """
        Use chmod to set the set-uid bit.
        """
        result = stdlib.default_commandline_executer(
            [str(shutil.which("chmod")), args, f"{bin_path}"]
        )
        assert result is not None, f"Failed to execute `chmod {args} {bin_path}"
        assert is_suid(bin_path.stat().st_mode)

        result.attack_id = "T1548.001"
        print()
        rich.print_json(result.to_json(indent=4, sort_keys=True))

    @pytest.mark.parametrize("args", ["--mode 4755", "--owner=root --mode=4755"])
    def test_install(self, args: str, bin_path: Path, tmp_path: Path):
        """
        Use install command to set the setuid bit.
        """
        folder = tmp_path / "tmp"
        folder.mkdir()

        result = stdlib.default_commandline_executer(
            [
                str(shutil.which("install")),
                *args.split(" "),
                f"{bin_path}",
                f"{folder}",
            ]
        )

        assert (
            result is not None
        ), f"Failed to execute `{str(shutil.which('install'))} {args} {bin_path} {folder}"
        dest = folder / bin_path.name

        assert is_suid(dest.stat().st_mode)
        result.attack_id = "T1548.001"
        print()
        rich.print_json(result.to_json(indent=4, sort_keys=True))

    @pytest.mark.parametrize("args", ["--chmod=4755 --perms"])
    def test_rsync(self, args: str, bin_path: Path, tmp_path: Path):
        """
        Use rsync to set the setuid bit.
        """
        dest = tmp_path / "tmp/newfile"
        dest.parent.mkdir()

        result = stdlib.default_commandline_executer(
            [
                str(shutil.which("rsync")),
                *args.split(" "),
                f"{bin_path}",
                f"{dest}",
            ]
        )

        assert (
            result is not None
        ), f"Failed to execute `{str(shutil.which('rsync'))} {args} {bin_path} {dest}"

        assert is_suid(dest.stat().st_mode)
        result.attack_id = "T1548.001"
        print()
        rich.print_json(result.to_json(indent=4, sort_keys=True))

    def test_syscall(self, bin_path: Path):
        """
        Use a syscall to set the setgid bit.
        """
        bin_path.chmod(0o4755)
        new_mode = bin_path.stat().st_mode
        assert is_suid(new_mode) == True
        result: StandardizedCompletedProcess = StandardizedCompletedProcess(
            "success", ""
        )
        result.attack_id = "T1548.001"
        result.pid = os.getpid()
        result.ppid = os.getppid()
        result.return_code = 0
        result.stdin = None
        result.stdout = None
        result.stderr = None
        result.md5 = stdlib.get_executable_md5(Path("python3"))
        print()
        rich.print_json(result.to_json(indent=4, sort_keys=True))


@pytest.mark.linux
class TestSetGid:
    @pytest.mark.parametrize("args", ["2755", "g+s", "--reference=myfile.txt"])
    def test_chmod(self, args: str, bin_path: Path):
        """
        Use `chmod` to set the set-gid bit.
        """
        result = stdlib.default_commandline_executer(
            [str(shutil.which("chmod")), args, f"{bin_path}"]
        )
        assert result is not None, f"Failed to execute `chmod {args} {bin_path}"
        assert is_sgid(bin_path.stat().st_mode)
        result.attack_id = "T1548.001"
        print()
        rich.print_json(result.to_json(indent=4, sort_keys=True))

    @pytest.mark.parametrize("args", ["--mode 2755", "--owner=root --mode=2755"])
    def test_install(self, args: str, bin_path: Path, tmp_path: Path):
        """
        Use `install` to set the setgid bit.
        """
        folder = tmp_path / "tmp"
        folder.mkdir()

        result = stdlib.default_commandline_executer(
            [
                str(shutil.which("install")),
                *args.split(" "),
                f"{bin_path}",
                f"{folder}",
            ]
        )

        assert (
            result is not None
        ), f"Failed to execute `{str(shutil.which('install'))} {args} {bin_path} {folder}"
        dest = folder / bin_path.name

        assert is_sgid(dest.stat().st_mode)

        result.attack_id = "T1548.001"
        print()
        rich.print_json(result.to_json(indent=4, sort_keys=True))

    @pytest.mark.parametrize("args", ["--chmod=2755 --perms"])
    def test_rsync(self, args: str, bin_path: Path, tmp_path: Path):
        """
        Use `rsync` to set the setgid bit
        """
        dest = tmp_path / "tmp/newfile"
        dest.parent.mkdir()

        result = stdlib.default_commandline_executer(
            [
                str(shutil.which("rsync")),
                *args.split(" "),
                f"{bin_path}",
                f"{dest}",
            ]
        )

        assert (
            result is not None
        ), f"Failed to execute `{str(shutil.which('rsync'))} {args} {bin_path} {dest}"

        assert is_sgid(dest.stat().st_mode)

        result.attack_id = "T1548.001"
        print()
        rich.print_json(result.to_json(indent=4, sort_keys=True))

    def test_syscall(self, bin_path: Path):
        """
        Use a syscall to set the setgid bit.
        """
        bin_path.chmod(0o2755)
        new_mode = bin_path.stat().st_mode
        assert is_sgid(new_mode) == True
        result: StandardizedCompletedProcess = StandardizedCompletedProcess(
            "success", ""
        )
        result.attack_id = "T1548.001"
        result.pid = os.getpid()
        result.ppid = os.getppid()
        result.return_code = 0
        result.stdin = None
        result.stdout = None
        result.stderr = None
        result.md5 = stdlib.get_executable_md5(Path("python3"))
        print()
        rich.print_json(result.to_json(indent=4, sort_keys=True))
