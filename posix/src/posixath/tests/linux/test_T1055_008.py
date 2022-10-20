import rich
import pytest
from pathlib import Path
from ...utils import ptrace
from subprocess import Popen, PIPE
from shutil import which
from ...utils.common import LinuxSTDLib as stdlib
from ...utils.common import StandardizedCompletedProcess


def verify_regs(regs: ptrace.user_regs_struct):
    """
    This is checking for registers with user mode pointers. It assumes that
    if it sees a value that begins with 0x7F0000000000 then it is a user mode
    pointer and that means it successfully got register values
    """
    if regs.rax & 0x7F0000000000 == 0x7F0000000000:
        return True
    if regs.rbx & 0x7F0000000000 == 0x7F0000000000:
        return True
    if regs.rcx & 0x7F0000000000 == 0x7F0000000000:
        return True
    if regs.rdx & 0x7F0000000000 == 0x7F0000000000:
        return True
    if regs.r15 & 0x7F0000000000 == 0x7F0000000000:
        return True
    if regs.r14 & 0x7F0000000000 == 0x7F0000000000:
        return True
    if regs.r13 & 0x7F0000000000 == 0x7F0000000000:
        return True
    if regs.r12 & 0x7F0000000000 == 0x7F0000000000:
        return True
    if regs.r11 & 0x7F0000000000 == 0x7F0000000000:
        return True
    if regs.r10 & 0x7F0000000000 == 0x7F0000000000:
        return True
    if regs.r9 & 0x7F0000000000 == 0x7F0000000000:
        return True
    if regs.r8 & 0x7F0000000000 == 0x7F0000000000:
        return True
    if regs.rip & 0x7F0000000000 == 0x7F0000000000:
        return True
    return False


# The following fixtures allow access to command line arguments
@pytest.fixture(scope="session")
def shellcode_path(pytestconfig: pytest.Config):
    """
    The path to a file containing shell code to be injected into a target process.
    """
    return pytestconfig.getoption("shellcode_path")


@pytest.fixture(scope="session")
def target_proc(pytestconfig: pytest.Config):
    """
    The path to a process that will be used in a process injection test.
    """
    return pytestconfig.getoption("target_proc")


@pytest.fixture(scope="session")
def target_args(pytestconfig: pytest.Config):
    """
    The arguments to the target process that will be used in a process injection test.
    If there are multiple arguments they should be entered as a single string. For
    example:
        pytest -v -k ptrace --target-proc="/usr/bin/ls" --target-args="-laR /etc"
    will run the command `/usr/bin/ls -laR /etc`
    """
    return pytestconfig.getoption("target_args")


def _build_standard_result() -> StandardizedCompletedProcess:
    result: StandardizedCompletedProcess = StandardizedCompletedProcess(
        "success", "", which("python3")
    )
    result.attack_id = "T1055.008"
    result.return_code = 0
    result.stdin = None
    result.stdout = None
    result.stderr = None
    result.md5 = stdlib.get_executable_md5(Path("python3"))
    return result


def _print_result(tpid: int, cmds: list[str]) -> None:
    result = _build_standard_result()
    setattr(result, "ptrace_cmds", cmds)
    setattr(result, "target_pid", tpid)
    print()
    rich.print_json(result.to_json(indent=4, sort_keys=True))


@pytest.fixture()
def target_pid(
    target_proc: Path | None,
    target_args: str | None,
):
    """
    Create a process and return its pid.

    Upone completion of the test terminate the process
    """
    if target_proc is not None:
        if target_args is not None:
            p = Popen([str(target_proc), *target_args.split(" ")], stdout=PIPE)
        else:
            p = Popen([str(target_proc)], stdout=PIPE)
    else:
        p = Popen(["sleep", "1"], stdout=PIPE)
    target_pid = p.pid
    yield target_pid
    p.terminate()


@pytest.mark.linux
class TestPtrace:
    def test_ptrace_write_poke(self, target_pid: int):
        """
        Covers PTRACE_POKETEXT/PTRACE_POKEDATA/PTRACE_POKEUSER.

        Arguments --target-proc, --target-args
        """
        # Attach to process
        result = ptrace.ptrace_attach(target_pid)
        assert result == 0, "Failed to attach to process"

        segments: list[ptrace.MemorySegment] | None = ptrace.get_proc_maps(target_pid)
        num_bytes = 8
        assert len(segments) > 0

        data = ptrace.ptrace_read_mem(target_pid, segments[0].start_addr, num_bytes)
        assert data is not None
        assert b"\x7fELF" in data

        data = data.replace(b"\x7f", b"\xAA")

        result = ptrace.ptrace_write_mem(target_pid, segments[0].start_addr, data)
        assert result == 0

        written_data = ptrace.ptrace_read_mem(
            target_pid, segments[0].start_addr, num_bytes
        )
        assert written_data is not None
        assert b"\xAAELF" in written_data

        ptrace.ptrace_detach(target_pid)
        _print_result(
            target_pid,
            ["PTRACE_ATTACH", "PTRACE_PEEKTEXT", "PTRACE_POKETEXT", "PTRACE_DETACH"],
        )

    def test_ptrace_write_regs(self, target_pid: int):
        """
        Covers PTRACE_SETREGS/PTRACE_SETFPREGS/PTRACE_SETREGSET.

        Arguments --target-proc, --target-args
        """
        result = ptrace.ptrace_attach(target_pid)
        assert result == 0, "Failed to attach to process"

        regs = ptrace.ptrace_get_regs(target_pid)
        assert verify_regs(regs), f"Failed to verify we got the gp regs: {regs}"

        old_rax = regs.rax
        regs.rax = 0x0102030405060708
        assert ptrace.ptrace_write_regs(target_pid, regs) == 0

        written_regs = ptrace.ptrace_get_regs(target_pid)
        assert written_regs.rax == 0x0102030405060708

        regs.rax = old_rax
        assert ptrace.ptrace_write_regs(target_pid, regs) == 0

        ptrace.ptrace_detach(target_pid)
        _print_result(
            target_pid,
            ["PTRACE_ATTACH", "PTRACE_GETREGS", "PTRACE_SETREGS", "PTRACE_DETACH"],
        )

    def test_ptrace_modify_sigmask(self, target_pid: int):
        """
        Covers PTRACE_SETSIGMASK.

        Arguments --target-proc, --target-args
        """
        # define sigmask(sig) 1u << (sig - 1)

        result = ptrace.ptrace_attach(target_pid)
        assert result == 0, "Failed to attach to process"

        mask = 1 << (30 - 1)
        assert ptrace.ptrace_set_sigmask(target_pid, mask) == 0

        written_mask = ptrace.ptrace_get_sigmask(target_pid)
        assert written_mask == mask
        _print_result(
            target_pid,
            [
                "PTRACE_ATTACH",
                "PTRACE_SETSIGMASK",
                "PTRACE_GETSIGMASK",
                "PTRACE_DETACH",
            ],
        )

    def test_ptrace_read_peek(self, target_pid: int):
        """
        Covers PTRACE_PEEKTEXT/PTRACE_PEEKDATA/PTRACE_PEEKUSR.

        Arguments --target-proc, --target-args
        """
        result = ptrace.ptrace_attach(target_pid)
        assert result == 0, "Failed to attach to process"

        segments: list[ptrace.MemorySegment] | None = ptrace.get_proc_maps(target_pid)
        num_bytes = 32
        assert segments is not None
        assert len(segments) > 0

        data = ptrace.ptrace_read_mem(target_pid, segments[0].start_addr, num_bytes)
        assert data is not None
        assert b"\x7fELF" in data

        ptrace.ptrace_detach(target_pid)
        _print_result(target_pid, ["PTRACE_ATTACH", "PTRACE_PEEKTEXT", "PTRACE_DETACH"])

    def test_ptrace_read_regs(self, target_pid: int):
        """
        Covers PTRACE_GETREGS/PTRACE_GETFPREGS/PTRACE_GETREGSET.

        Arguments --target-proc, --target-args
        """
        result = ptrace.ptrace_attach(target_pid)
        assert result == 0, "Failed to attach to process"

        regs = ptrace.ptrace_get_regs(target_pid)
        assert verify_regs(regs), f"Failed to verify we got the gp regs: {regs}"

        ptrace.ptrace_detach(target_pid)
        _print_result(target_pid, ["PTRACE_ATTACH", "PTRACE_GETREGS", "PTRACE_DETACH"])

    def test_ptrace_read_tls(self, target_pid: int):
        """
        Covers PTRACE_GET_THREAD_AREA.

        Arguments --target-proc, --target-args
        """
        # Attach to process
        result = ptrace.ptrace_attach(target_pid)
        assert result == 0, "Failed to attach to process"

        desc: ptrace.user_desc | None = ptrace.ptrace_get_thread_area(target_pid, 12)
        assert desc is not None
        assert desc.entry_number == 12
        _print_result(
            target_pid, ["PTRACE_ATTACH", "PTRACE_GET_THREAD_AREA", "PTRACE_DETACH"]
        )

    def test_ptrace_shellcode_injection(
        self,
        shellcode_path: Path | None,
        target_proc: Path | None,
        target_args: list[str] | None,
    ):
        """
        Does a full shell code injection into a child process.

        Arguments --shellcode-path, --target-proc, --target-args
        """

        """
        Shell code
        ; It was assembled with `nasm -felf64 shellcode.asm`

        global    _start
        section   .text
        _start:
            mov       rax, 1              ; system call for write
            mov       rdi, 1              ; file handle 1 is stdout
            lea       rsi, [rel message]  ; address of string to output, RIP-relative
            mov       rdx, 13             ; number of bytes in string
            syscall                       ; call the `write` syscall
            mov       rax, 60             ; system call for exit
            mov       rdi, 42             ; exit code 42
            syscall                       ; invoke operating system to exit

        section   .data
        message:
            db        "Hello, World", 10  ; note the newline at the end
        """
        # Create a process
        if target_proc is not None:
            if target_args is not None:
                p = Popen([str(target_proc), *target_args], stdout=PIPE)
            else:
                p = Popen([str(target_proc)], stdout=PIPE)
        else:
            p = Popen(["sleep", "1"], stdout=PIPE)

        target_pid = p.pid

        # Attach to process
        result = ptrace.ptrace_attach(target_pid)
        assert result == 0, "Failed to attach to process"

        # Write shell code to the process memory space
        regs: ptrace.user_regs_struct = ptrace.ptrace_get_regs(target_pid)

        # Shell code just prints "Hello, world\n" which the `sleep` binary does not do
        if shellcode_path is None:
            shellcode = b"\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\x8d\x35\x12\x00\x00\x00\xba\x0d\x00\x00\x00\x0f\x05\xb8\x3c\x00\x00\x00\x48\x83\xf7\x2b\x0f\x05\x48\x65\x6c\x6c\x6f\x2c\x20\x77\x6f\x72\x6c\x64\x0a"

        else:
            shellcode = shellcode_path.read_bytes()

        assert ptrace.ptrace_write_mem(target_pid, regs.rip, shellcode) == 0

        # Point RIP to the beginning of our shell code
        assert ptrace.ptrace_write_regs(target_pid, regs) == 0

        # Continue process
        ptrace.ptrace_detach(target_pid)

        # Only validate output when it is our shellcode being run
        if shellcode_path is None:
            # Verify that hello world got printed to stdout
            assert p.communicate()[0] == b"Hello, world\n"

            # The return code is set to something specific just to show we have control
            assert p.returncode == 42

            # The process is probably already gone because we waited with the call to communicate
            p.terminate()
        _print_result(
            target_pid,
            [
                "PTRACE_ATTACH",
                "PTRACE_GETREGS",
                "PTRACE_POKETEXT",
                "PTRACE_SETREGS",
                "PTRACE_DETACH",
            ],
        )
