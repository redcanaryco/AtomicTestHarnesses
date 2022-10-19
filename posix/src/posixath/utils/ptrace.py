from errno import ENOENT
import os
import sys
import ctypes
import struct
from pathlib import Path

# Used for the PTRACE_GET_SYSCALLINFO op field
PTRACE_SYSCALL_INFO_NONE = 0
PTRACE_SYSCALL_INFO_ENTRY = 1
PTRACE_SYSCALL_INFO_EXIT = 2
PTRACE_SYSCALL_INFO_SECCOMP = 3

# ptrace actions
PTRACE_TRACEME = 0
PTRACE_PEEKTEXT = 1
PTRACE_PEEKDATA = 2
PTRACE_PEEKUSR = 3
PTRACE_POKETEXT = 4
PTRACE_POKEDATA = 5
PTRACE_POKEUSR = 6
PTRACE_CONT = 7
PTRACE_KILL = 8
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_GETFPREGS = 14
PTRACE_SETFPREGS = 15
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_GETFPXREGS = 18
PTRACE_SETFPXREGS = 19
PTRACE_SYSCALL = 24
PTRACE_GET_THREAD_AREA = 25
PTRACE_SET_THREAD_AREA = 26
PTRACE_ARCH_PRCTL = 30
PTRACE_SYSEMU = 31
PTRACE_SYSEMU_SINGLESTEP = 32
PTRACE_SINGLEBLOCK = 33
# 0x4200-0x4300 are reserved for architecture-independent additions.  */
PTRACE_SETOPTIONS = 0x4200
PTRACE_GETEVENTMSG = 0x4201
PTRACE_GETSIGINFO = 0x4202
PTRACE_SETSIGINFO = 0x4203
PTRACE_GETSIGMASK = 0x420A
PTRACE_SETSIGMASK = 0x420B
PTRACE_SECCOMP_GET_FILTER = 0x420C
PTRACE_GET_SYSCALL_INFO = 0x420E

if sys.platform == "linux":
    LIBC = ctypes.CDLL(os.environ.get("LIBC_PATH", "libc.so.6"), use_errno=True)
    ptrace = LIBC.ptrace
    ptrace.argtypes = [
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    ptrace.restype = ctypes.c_uint64

WORD_SIZE = 8 if sys.maxsize > 2**32 else 4


class PtraceBadAlignment(Exception):
    pass


# Used for the sigset_t type
_SIGSET_NWORDS = 1024 // (8 * ctypes.sizeof(ctypes.c_ulong))


class sigset_t(ctypes.Structure):
    """
    typedef struct
    {
        unsigned long int __val[_SIGSET_NWORDS];
    } __sigset_t;
    """

    _fields_ = [("__val", ctypes.c_ulong * _SIGSET_NWORDS)]


class _entry(ctypes.Structure):
    _fields_ = [("nr", ctypes.c_uint64), ("args", ctypes.c_uint64 * 6)]


class _exit(ctypes.Structure):
    _fields_ = [("rval", ctypes.c_int64), ("is_error", ctypes.c_uint8)]


class _seccomp(ctypes.Structure):
    _fields = [
        ("nr", ctypes.c_uint64),
        ("args", ctypes.c_uint64 * 6),
        ("ret_data", ctypes.c_uint32),
    ]


class _U(ctypes.Union):
    _fields_ = [("entry", _entry), ("exit", _exit), ("seccomp", _seccomp)]


class ptrace_syscall_info(ctypes.Structure):
    """
    struct ptrace_syscall_info {
        __u8 op;    /* PTRACE_SYSCALL_INFO_* */
        __u8 pad[3];
        __u32 arch;
        __u64 instruction_pointer;
        __u64 stack_pointer;
        union {
            struct {
                __u64 nr;
                __u64 args[6];
            } entry;
            struct {
                __s64 rval;
                __u8 is_error;
            } exit;
            struct {
                __u64 nr;
                __u64 args[6];
                __u32 ret_data;
            } seccomp;
        };
    };
    """

    _anonymous_ = ("u",)
    _fields_ = [
        ("op", ctypes.c_uint8),
        ("pad", ctypes.c_uint8 * 3),
        ("arch", ctypes.c_uint32),
        ("instruction_pointer", ctypes.c_uint64),
        ("stack_pointer", ctypes.c_uint64),
        ("u", _U),
    ]


class user_regs_struct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_uint64),
        ("r14", ctypes.c_uint64),
        ("r13", ctypes.c_uint64),
        ("r12", ctypes.c_uint64),
        ("rbp", ctypes.c_uint64),
        ("rbx", ctypes.c_uint64),
        ("r11", ctypes.c_uint64),
        ("r10", ctypes.c_uint64),
        ("r9", ctypes.c_uint64),
        ("r8", ctypes.c_uint64),
        ("rax", ctypes.c_uint64),
        ("rcx", ctypes.c_uint64),
        ("rdx", ctypes.c_uint64),
        ("rsi", ctypes.c_uint64),
        ("rdi", ctypes.c_uint64),
        ("orig_rax", ctypes.c_uint64),
        ("rip", ctypes.c_uint64),
        ("cs", ctypes.c_uint64),
        ("eflags", ctypes.c_uint64),
        ("rsp", ctypes.c_uint64),
        ("ss", ctypes.c_uint64),
        ("fs_base", ctypes.c_uint64),
        ("gs_base", ctypes.c_uint64),
        ("ds", ctypes.c_uint64),
        ("es", ctypes.c_uint64),
        ("fs", ctypes.c_uint64),
        ("gs", ctypes.c_uint64),
    ]

    def __str__(self):
        result = f"r15 -> 0x{self.r15:016x}\n"
        result += f"r14 -> 0x{self.r14:016x}\n"
        result += f"r13 -> 0x{self.r13:016x}\n"
        result += f"r12 -> 0x{self.r12:016x}\n"
        result += f"r11 -> 0x{self.r11:016x}\n"
        result += f"r10 -> 0x{self.r10:016x}\n"
        result += f"r9  -> 0x{self.r9:016x}\n"
        result += f"r8  -> 0x{self.r8:016x}\n"
        result += f"rax -> 0x{self.rax:016x}\n"
        result += f"rbx -> 0x{self.rbx:016x}\n"
        result += f"rcx -> 0x{self.rcx:016x}\n"
        result += f"rdx -> 0x{self.rdx:016x}\n"
        result += f"rip -> 0x{self.rip:016x}\n"
        result += f"rsp -> 0x{self.rsp:016x}\n"
        result += f"eflags -> 0x{self.eflags:016x}\n"
        return result


class user_desc(ctypes.Structure):
    """
    Structure used to describe TLS section.
    """

    _fields_ = [
        ("entry_number", ctypes.c_uint),
        ("base_addr", ctypes.c_uint),
        ("limit", ctypes.c_uint),
        ("seg_32bit", ctypes.c_uint, 1),
        ("contents", ctypes.c_uint, 2),
        ("read_exec_only", ctypes.c_uint, 1),
        ("limit_in_pages", ctypes.c_uint, 1),
        ("seg_not_present", ctypes.c_uint, 1),
        ("useable", ctypes.c_uint, 1),
    ]

    def __str__(self):
        result: str = f"entry_number:    0x{self.entry_number:08x}\n"
        result += f"base_addr:       0x{self.base_addr:08x}\n"
        result += f"limit:           0x{self.limit:08x}\n"
        result += f"seg_32bit:       {self.seg_32bit}\n"
        result += f"contents:        {self.contents}\n"
        result += f"read_exec_only:  {self.read_exec_only}\n"
        result += f"limit_in_pages:  {self.limit_in_pages}\n"
        result += f"seg_not_present: {self.seg_not_present}\n"
        result += f"useable:         {self.useable}\n"
        return result


class sock_filter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint16),
        ("jt", ctypes.c_uint8),
        ("jf", ctypes.c_uint8),
        ("k", ctypes.c_uint32),
    ]


class MemorySegment:
    def __init__(
        self,
        addrs: bytes,
        perms: bytes,
        offset: bytes | None = None,
        dev: bytes | None = None,
        inode: bytes | None = None,
        pathname: bytes | None = None,
    ):
        self.start_addr = int(addrs.split(b"-")[0], base=16)
        self.end_addr = int(addrs.split(b"-")[1], base=16)
        self.perms = perms
        self.executable = b"x" in perms
        self.readable = b"r" in perms
        self.writable = b"w" in perms
        self.path = Path(pathname.decode()) if pathname is not None else pathname
        self.offset = offset
        self.dev = dev
        self.inode = inode
        if self.dev is not None:
            self.dev_maj = self.dev.split(b":")[0]
            self.dev_min = self.dev.split(b":")[1]

    @staticmethod
    def from_line(line: bytes):
        """
        Create a new memory segment from a line of /proc/<pid>/maps.
        """
        addrs: bytes
        perms: bytes
        offset: bytes
        dev: bytes
        inode: bytes
        pathname: bytes
        try:
            data = line.split()
            addrs: bytes
            perms: bytes
            offset: bytes
            dev: bytes
            inode: bytes
            if len(data) == 5:
                addrs, perms, offset, dev, inode = data
                return MemorySegment(addrs, perms, offset=offset, dev=dev, inode=inode)
            elif len(data) == 6:
                pathname: bytes
                addrs, perms, offset, dev, inode, pathname = data
                return MemorySegment(
                    addrs, perms, offset=offset, dev=dev, inode=inode, pathname=pathname
                )
            else:
                raise Exception("Unknown number of /proc/maps entries")
        except Exception as e:
            print(f"Got exception during parsing proc maps: {e}")
            return None

    def __str__(self):
        return f"0x{self.start_addr:x}-0x{self.end_addr:x} {self.perms} {self.offset} {self.dev} {self.inode}\t{self.path if self.path is not None else ''}"


def get_proc_maps(target_pid: int) -> list[MemorySegment]:
    """
    Get the memory segments that correspond to the native binary
    """
    result: list[MemorySegment] = []
    try:
        comm: str = open(f"/proc/{target_pid}/comm", "r").read().strip()
    except Exception as e:
        print(f"Exception occured getting comm string\n{e}")
        return []

    try:
        with open(f"/proc/{target_pid}/maps", "rb") as f:
            for line in f:
                seg: MemorySegment | None = MemorySegment.from_line(line)
                if seg is not None:
                    result.append(seg)
                else:
                    print(f"Failed to parse proc maps line: {line}")

        # Only get segments that match the binary name
        return [x for x in result if x.path is not None and comm in x.path.name]
    except Exception as e:
        print(f"Exception occured while reading /proc/{target_pid}/maps\n{e}")
        return []


def get_exec_maps(target_pid: int) -> list[MemorySegment]:
    """
    Get the memory segments that are exectuable
    """
    result: list[MemorySegment] = []
    try:
        with open(f"/proc/{target_pid}/maps", "rb") as f:
            for line in f:
                seg: MemorySegment | None = MemorySegment.from_line(line)
                if seg is not None:
                    result.append(seg)
                else:
                    print("Failed to parse proc maps line")
        return result
    except Exception as e:
        print(f"Exception occured while reading /proc/{target_pid}/maps\n{e}")
        return []


def ptrace_get_sigmask(target_pid: int):
    ptrace.argtypes = [
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    ptrace.restype = ctypes.c_uint64
    mask = ctypes.c_ulong(0)
    result = ptrace(
        PTRACE_GETSIGMASK, target_pid, ctypes.sizeof(ctypes.c_ulong), ctypes.byref(mask)
    )
    assert result == 0
    return mask.value


def ptrace_set_sigmask(target_pid: int, mask: int):
    ptrace.argtypes = [
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    ptrace.restype = ctypes.c_uint64
    durp = ctypes.c_ulong(mask)
    return ptrace(
        PTRACE_SETSIGMASK,
        target_pid,
        ctypes.sizeof(ctypes.c_ulong),
        ctypes.byref(durp),
    )


def ptrace_attach(target_pid: int):
    ptrace.argtypes = [
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    ptrace.restype = ctypes.c_uint64
    result = ptrace(PTRACE_ATTACH, target_pid, None, None)
    if result == -1:
        return -1

    _, return_status = os.waitpid(target_pid, 0)
    if os.WIFSTOPPED(return_status):
        return 0
    else:
        return -1


def ptrace_get_thread_area(target_pid: int, index: int) -> user_desc | None:
    """
    Get the TLS section located at `index`.
    """
    ptrace.argtypes = [
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.POINTER(user_desc),
    ]
    ptrace.restype = ctypes.c_uint64

    desc = user_desc()
    result = ptrace(PTRACE_GET_THREAD_AREA, target_pid, index, ctypes.byref(desc))
    if result == -1:
        return None
    return desc


def ptrace_set_thread_area(target_pid: int, index: int, desc: user_desc):
    """
    Set the TLS section located at `index`.
    """
    ptrace.argtypes = [
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.POINTER(user_desc),
    ]
    ptrace.restype = ctypes.c_uint64
    result = ptrace(PTRACE_SET_THREAD_AREA, target_pid, index, ctypes.byref(desc))
    if result != 0:
        print(f"errno: {ctypes.get_errno()}")
    return result


def ptrace_detach(target_pid: int):
    ptrace.argtypes = [
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    ptrace.restype = ctypes.c_uint64
    return ptrace(PTRACE_DETACH, target_pid, None, None)


def ptrace_get_regs(target_pid: int):
    """
    Get the general purpose registers from the target process
    """
    regs = user_regs_struct()
    ptrace.argtypes = [
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.POINTER(user_regs_struct),
    ]
    ptrace.restype = ctypes.c_uint64
    ptrace(PTRACE_GETREGS, target_pid, None, ctypes.byref(regs))
    return regs


def ptrace_write_regs(target_pid: int, regs: user_regs_struct):
    """
    Get the general purpose registers from the target process
    """
    ptrace.argtypes = [
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.POINTER(user_regs_struct),
    ]
    ptrace.restype = ctypes.c_uint64
    return ptrace(PTRACE_SETREGS, target_pid, None, ctypes.byref(regs))


def ptrace_write_mem(target_pid: int, addr: int | None, data: bytes):
    ptrace.argtypes = [
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    ptrace.restype = ctypes.POINTER(ctypes.c_uint64)
    if len(data) % WORD_SIZE != 0:
        raise PtraceBadAlignment(f"`data` needs to be aligned to {WORD_SIZE} bytes")

    if addr is None:
        return None

    for i in range(len(data) // WORD_SIZE):
        result = ptrace(
            PTRACE_POKETEXT,
            target_pid,
            addr + i * WORD_SIZE,
            struct.unpack("Q", data[i * WORD_SIZE : (i + 1) * WORD_SIZE])[0],
        )
        if result == -1:
            return None

    return 0


def ptrace_get_syscall_info(target_pid: int):
    ptrace.argtypes = [
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_void_p,
    ]
    ptrace.restype = ctypes.c_uint64
    info = ptrace_syscall_info()
    ptrace(
        PTRACE_GET_SYSCALL_INFO,
        target_pid,
        ctypes.sizeof(ptrace_syscall_info),
        ctypes.byref(info),
    )
    return info


def ptrace_syscall(target_pid: int):
    ptrace.argtypes = [
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    ptrace.restype = ctypes.c_uint64
    ptrace(PTRACE_SYSCALL, target_pid, 0, 0)
    _, return_status = os.waitpid(target_pid, 0)
    if os.WIFSTOPPED(return_status):
        return 0
    else:
        return -1


def ptrace_get_seccomp_filters(target_pid: int):
    result: list[list[sock_filter]] = []
    ptrace.argtypes = [
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_void_p,
    ]
    ptrace.restype = ctypes.c_uint64
    ret = 0
    index = 0
    while True:
        ret = ptrace(PTRACE_SECCOMP_GET_FILTER, target_pid, index, None)
        if ret == ENOENT:
            break

        buf = ctypes.create_string_buffer(ret)
        ret = ptrace(PTRACE_SECCOMP_GET_FILTER, target_pid, index, buf)


def ptrace_read_mem(target_pid: int, addr: int | None, num_bytes: int):
    ptrace.argtypes = [
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    ptrace.restype = ctypes.POINTER(ctypes.c_uint64)
    if num_bytes % WORD_SIZE != 0:
        raise PtraceBadAlignment(f"num_bytes needs to be aligned to {WORD_SIZE} bytes")

    if addr is None:
        return None

    buf = ctypes.create_string_buffer(num_bytes)
    for i in range(num_bytes // WORD_SIZE):
        result = ptrace(PTRACE_PEEKTEXT, target_pid, addr + i * WORD_SIZE, None)
        if result == -1:
            return None
        else:
            ctypes.memmove(
                ctypes.addressof(buf) + i * WORD_SIZE,
                ctypes.byref(result),
                ctypes.sizeof(result),
            )

    return buf.raw


def ptrace_cont(target_pid: int):
    """
    Continue a stopped process
    """
    ptrace.argtypes = [
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    ptrace.restype = ctypes.c_uint64
    return ptrace(PTRACE_CONT, target_pid, 0, 0)
