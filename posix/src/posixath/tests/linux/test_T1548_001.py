"""
Set of tests for Attack Technique T1548.001 (setuid/setgid)
"""
import os
import sys
import stat
import rich
import pytest
import shutil
import ctypes
import sysconfig
import psutil
from subprocess import run, Popen
from time import sleep

from pathlib import Path
from _pytest.fixtures import SubRequest
from ...utils.common import LinuxSTDLib as stdlib, StandardizedCompletedProcess


# Check if we are being run by our test runner or by pytest directly
if "PYTEST_CURRENT_TEST" in os.environ:
    package_path = "./"
else:
    MODULE_NAME = "posixath"
    package_path = os.path.join(sysconfig.get_paths()["purelib"], MODULE_NAME)

libcap = None
if sys.platform == "linux":
    libcap = ctypes.cdll.LoadLibrary("libcap.so")
    # cap_t cap_get_file(const char *path_p)
    libcap.cap_get_file.argtypes = [ctypes.c_char_p]
    libcap.cap_get_file.restype = ctypes.c_void_p

    # char* cap_to_text(cap_t caps, ssize_t *length_p)
    libcap.cap_to_text.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    libcap.cap_to_text.restype = ctypes.c_char_p


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


def get_proc_uid(pid: int) -> int:
    try:
        return int(
            run(["stat", "-c", "%u", f"/proc/{pid}"], capture_output=True).stdout
        )
    except Exception:
        return -1


def get_proc_gid(pid: int) -> int:
    try:
        return int(
            run(["stat", "-c", "%g", f"/proc/{pid}"], capture_output=True).stdout
        )
    except Exception:
        return -1


def get_file_caps(path: Path) -> str:
    """
    Attempts to get the capabilities of a file.

    If no capabilities exist on the file an empty string is returned
    If there is an error collecting the capabilities and empty string is returned
    """
    if libcap is not None:
        cap_t = libcap.cap_get_file(str(path).encode("utf-8"))
        if cap_t is None:
            return ""
        else:
            return libcap.cap_to_text(cap_t, None).decode("utf-8")
    else:
        raise Exception("Cannot parse capabilities without libcap installed")


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


@pytest.fixture
def make_bins():
    run(["make", "-C", package_path + "/tests/linux/library/T1548_001/"], check=True)

    yield

    run(
        ["make", "-C", package_path + "/tests/linux/library/T1548_001/", "clean"],
        check=True,
    )


# Run before all test run
@pytest.fixture(scope="session", autouse=True)
def run_before_tests(request: SubRequest):
    assert os.geteuid() == 0, "T1548.001 tests must be run as root"

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
    assert is_suid(mode) is False

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
        assert is_suid(new_mode) is True
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

    @pytest.mark.usefixtures("make_bins")
    def test_add_setuid_cap(self, bin_path: Path, tmp_path: Path) -> None:
        """
        Runs the setcap tool to add the CAP_SETUID capability to a file.
        """
        # Make sure that the setcap tool is present on the host
        assert (
            shutil.which("setcap") is not None
        ), "setcap must be present on the system"

        # Run `setcap cap_setuid=ep /path/to/file`
        dest = tmp_path / "newfile"
        dest.parent.mkdir(exist_ok=True)
        dest.touch()

        result = stdlib.default_commandline_executer(
            [
                str(shutil.which("setcap")),
                "cap_setuid=ep",
                f"{dest}",
            ]
        )

        # Verify the command succeeded
        assert (
            result is not None
        ), f"Failed to execute `{str(shutil.which('setcap'))}  {bin_path} {dest}"

        print(result.stdout)

        assert get_file_caps(dest) == "cap_setuid=ep"
        result.attack_id = "T1548.001"
        print()
        rich.print_json(result.to_json(indent=4, sort_keys=True))

    @pytest.mark.usefixtures("make_bins")
    def test_run_setuid_binary(self, bin_path: Path) -> None:
        """
        Runs a binary that has the setuid bit set.

        It runs the binary as the logged in user. It is best to be logged in as
        an unprivileged user.
        """
        setuid_path: str = package_path + "/tests/linux/library/T1548_001/do_setuid"

        # Copying it here so it can be in a globally visible directory
        run(["cp", setuid_path, "/usr/local/bin"], check=True)

        # Setting the setuid bit and owner as root
        run(["chown", "root:root", "/usr/local/bin/do_setuid"], check=True)
        run(["chmod", "u+xs", "/usr/local/bin/do_setuid"], check=True)

        # Run the command as the logged in user. This should not be root but rather a normal user
        proc = Popen(["sudo", "-u", os.getlogin(), "/usr/local/bin/do_setuid"])
        result: StandardizedCompletedProcess = StandardizedCompletedProcess(
            "success", setuid_path, setuid_path
        )

        # Sleeping to give the process time to start up
        sleep(0.5)

        result.uid = get_proc_uid(proc.pid)
        result.gid = get_proc_gid(proc.pid)
        result.pid = proc.pid
        result.ppid = os.getpid()
        result.return_code = proc.wait()
        result.attack_id = "T1548.001"

        print()
        rich.print_json(result.to_json(indent=4, sort_keys=True))
        run(["rm", "/usr/local/bin/do_setuid"])

    @pytest.mark.usefixtures("make_bins")
    def test_run_setuid_cap_binary(self, bin_path: Path) -> None:
        """
        Runs a binary that has the CAP_SETUID capability and attempts to set it's uid
        """
        # Give the capability the setuid capability
        setuid_path: str = package_path + "/tests/linux/library/T1548_001/do_setuid"

        # Copying it here so it can be in a globally visible directory
        run(["cp", setuid_path, "/usr/local/bin"], check=True)
        run(
            [str(shutil.which("setcap")), "cap_setuid=ep", "/usr/local/bin/do_setuid"],
            check=True,
        )

        # Run the command as the logged in user. This should not be root but rather a normal user
        pproc = Popen(["sudo", "-u", os.getlogin(), "/usr/local/bin/do_setuid"])
        result: StandardizedCompletedProcess = StandardizedCompletedProcess(
            "success", setuid_path, setuid_path
        )

        # Sleeping to give the process time to start up
        sleep(0.5)
        proc: psutil.Process = psutil.Process(pproc.pid)

        result.uid = get_proc_uid(proc.children()[0].pid)
        result.gid = get_proc_gid(proc.children()[0].pid)
        result.pid = pproc.pid
        result.ppid = os.getpid()
        result.return_code = pproc.wait()
        result.attack_id = "T1548.001"

        print()
        rich.print_json(result.to_json(indent=4, sort_keys=True))
        run(["rm", "/usr/local/bin/do_setuid"])


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
        assert is_sgid(new_mode) is True
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

    def test_add_setgid_cap(self, tmp_path: Path) -> None:
        """
        Runs the setcap utility to add the CAP_SETGID capability to file.
        """
        assert (
            shutil.which("setcap") is not None
        ), "setcap must be present on the system"
        dest = tmp_path / "newfile"
        dest.parent.mkdir(exist_ok=True)
        dest.touch()

        result = stdlib.default_commandline_executer(
            [
                str(shutil.which("setcap")),
                "cap_setgid=ep",
                f"{dest}",
            ]
        )

        assert (
            result is not None
        ), f"Failed to execute `{str(shutil.which('setcap'))} {dest}"

        print(result.stdout)

        assert get_file_caps(dest) == "cap_setgid=ep"
        result.attack_id = "T1548.001"
        print()
        rich.print_json(result.to_json(indent=4, sort_keys=True))

    @pytest.mark.usefixtures("make_bins")
    def test_run_setgid_binary(self) -> None:
        """
        Runs a binary with the setgid bit set and is owned by root.

        The binary is run as the logged on user (making the assumption it is an
        unprivileged user).
        """
        setgid_path: str = package_path + "/tests/linux/library/T1548_001/do_setgid"

        # Copying it here so it can be in a globally visible directory
        run(["cp", setgid_path, "/usr/local/bin"], check=True)

        # Setting the setgid bit and owner as root
        run(["chown", "root:root", "/usr/local/bin/do_setgid"], check=True)
        run(["chmod", "g+s", "/usr/local/bin/do_setgid"], check=True)

        # Run the command as the logged in user. This should not be root but rather a normal user
        # This creates a new process as a different user so we need to track the child process
        pproc = Popen(["sudo", "-u", os.getlogin(), "/usr/local/bin/do_setgid"])
        result: StandardizedCompletedProcess = StandardizedCompletedProcess(
            "success", setgid_path, setgid_path
        )

        # Sleeping to give the process time to start up
        sleep(0.5)
        proc = psutil.Process(pproc.pid)

        result.uid = get_proc_uid(proc.children()[0].pid)
        result.gid = get_proc_gid(proc.children()[0].pid)
        result.pid = pproc.pid
        result.ppid = os.getpid()
        result.return_code = pproc.wait()
        result.attack_id = "T1548.001"

        print()
        rich.print_json(result.to_json(indent=4, sort_keys=True))
        run(["rm", "/usr/local/bin/do_setgid"])

    @pytest.mark.usefixtures("make_bins")
    def test_run_setgid_cap_binary(self, bin_path: Path) -> None:
        """
        Runs a binary that has the CAP_SETGID capability and attempts to set it's gid.
        """
        # Give the capability the setgid capability
        setgid_path: str = package_path + "/tests/linux/library/T1548_001/do_setgid"

        # Copying it here so it can be in a globally visible directory
        run(["cp", setgid_path, "/usr/local/bin"], check=True)
        run(
            [str(shutil.which("setcap")), "cap_setgid=ep", "/usr/local/bin/do_setgid"],
            check=True,
        )

        # Run the command as the logged in user. This should not be root but rather a normal user
        pproc = Popen(["sudo", "-u", os.getlogin(), "/usr/local/bin/do_setgid"])
        result: StandardizedCompletedProcess = StandardizedCompletedProcess(
            "success", setgid_path, setgid_path
        )

        # Sleeping to give the process time to start up
        sleep(0.5)
        proc = psutil.Process(pproc.pid)

        result.uid = get_proc_uid(proc.children()[0].pid)
        result.gid = get_proc_gid(proc.children()[0].pid)
        result.pid = pproc.pid
        result.ppid = os.getpid()
        result.return_code = pproc.wait()
        result.attack_id = "T1548.001"

        print()
        rich.print_json(result.to_json(indent=4, sort_keys=True))
        run(["rm", "/usr/local/bin/do_setgid"])
