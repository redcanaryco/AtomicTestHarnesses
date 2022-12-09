import os
import sys
import json
import shutil
import logging
import getpass
import subprocess
from hashlib import md5
from pathlib import Path
from datetime import datetime
import xml.etree.ElementTree as ET

MIN_PY_V: tuple[int, int] = (3, 10)

PLATFORM: str = sys.platform
IS_DARWIN: bool = True if PLATFORM == "darwin" else False
IS_LINUX: bool = True if PLATFORM == "linux" else False

logger = logging.getLogger(__name__)


class StandardizedCompletedProcess:
    """
    A class to represent a completed process.
    """

    def __init__(self, result: str, argv: str, process_path: str | None = ""):
        self.activity_at_ts: str = (
            datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        )

        self.attack_id: str = ""
        self.result: str = result
        self.command_line: str = argv
        self.process_path: str | None = process_path
        self.pid: int = os.getpid()
        self.ppid: int = os.getppid()
        self.uid: int = os.getuid()
        self.gid: int = os.getgid()
        self.return_code: int = -1
        self.stdin: str | None = None
        self.stdout: str | None = None
        self.stderr: str | None = None
        self.cwd: str = os.getcwd()
        if self.process_path is not None:
            self.md5: str | None = STDLib.get_executable_md5(Path(self.process_path))

    def to_json(self, indent: int, sort_keys: bool) -> str:
        """
        Converts the StadardizedCompletedProcess to a json string
        """
        return json.dumps(self.__dict__, indent=indent, sort_keys=sort_keys)

    def __str__(self):
        result = f"StandardizedCompletedProcess {{\n"
        result += f"\tactivity_at_ts: {self.activity_at_ts}\n"
        result += f"\tresult: {self.result}\n"
        result += f"\tcommand_line: {self.command_line}\n"
        result += f"\tpid: {self.pid}\n"
        result += f"\tppid: {self.ppid}\n"
        result += f"\treturn_code: {self.return_code}\n"
        result += f"\tstdin: {self.stdin}\n"
        result += f"\tstdout: {self.stdout}\n"
        result += f"\tstderr: {self.stderr}\n"
        result += f"\tmd5: {self.md5}\n"
        result += f"}}"
        return result


class STDLib:
    """
    Contains methods for common AtomicTestHarness development tools.
    """

    def __init__(self):
        pass

    @staticmethod
    def get_username() -> str:
        """
        Get the username of the currently logged on user.

        :rtype: str, None
        """
        return getpass.getuser()

    @staticmethod
    def get_current_ts() -> str:
        return str(datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z")

    @staticmethod
    def file_perms_to_str(perms: int) -> str:
        """
        Converts an octal integer to the symbolink permission format.

        :param perms: The permission octal number
        :type int:
        :rtype: str
        """
        result: str = "-"
        base_perms = f"{perms & 0o777:03o}"
        perm_list: list[str] = ["---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx"]
        for d in [int(n) for n in base_perms]:
            result += perm_list[d]

        # Handle special bits
        if perms & 0o7000 != 0:
            if perms & 0o4000 != 0:
                if result[3] == "x":
                    result = result[:3] + "s" + result[4:]
                else:
                    result = result[:3] + "S" + result[4:]
            if perms & 0o2000 != 0:
                if result[6] == "x":
                    result = result[:6] + "s" + result[7:]
                else:
                    result = result[:6] + "S" + result[7:]
            if perms & 0o1000 != 0:
                if result[9] == "x":
                    result = result[:9] + "t" + result[10:]
                else:
                    result = result[:9] + "T" + result[10:]
        return result

    @staticmethod
    def get_md5(file_path: str | Path) -> str:
        """
        Computes the MD5 of the given file.

        :param file_path: The path to the file
        :type file_path: Path
        :returns: The MD5 hash of the file
        :rtype: str
        """
        if isinstance(file_path, Path):
            bin_data = file_path.read_bytes()
        else:
            bin_data = Path(file_path).read_bytes()
        return md5(bin_data).hexdigest()

    @staticmethod
    def get_executable_md5(file_path: Path) -> str | None:
        """
        Compute the MD5 of an exectuable located in $PATH

        :param file_path: The path to the file
        :type file_path: Path
        :returns: The hash or none if the file doesn't exist
        :rtype: str, None
        """
        bin_path: str | Path | None = shutil.which(file_path)
        if bin_path is None:
            return None

        return STDLib.get_md5(bin_path)

    @staticmethod
    def default_commandline_executer(
        argv: list[str], stdin: str | None = None
    ) -> StandardizedCompletedProcess | None:
        """
        Execute a basic command-line and provides back telemetry in the form of a StandardizedCompletedProcess.

        :param argv: The command line string to be executed formatted as a list
        :type argv: list
        :param stdin: Input to pass to the child process
        :type stdin: str
        :returns: An instance of StandardizedCompletedProcess
        :rtype: StandardizedCompletedProcess, None
        :raises subprocess.CalledProcessError: If Popen call fails
        :raises FileNotFoundError:
        :raises PermissionError:
        """
        try:
            # Execute the command-line
            ppid = os.getpid()
            process = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            # If there is user input that needs to be communicated to the process then do that now.
            process_error_result: str = ""
            if stdin is not None and len(stdin) > 0:
                process_result = process.communicate(str(stdin))
                process_error_result = process_result[0]
                # Wait for the child process to terminate.
                process.wait()
            else:
                # Otherwise, we'll still want the STDOUT from the executed technique
                process_result = process.communicate()

            # Condense into a single string
            process_stdout_result = " ".join(process_result)

            # Check to ensure the process exited gracefully.
            returncode: int = process.returncode

            # Fill in the results and return!
            process_execution_message: str = (
                "success" if returncode == 0 or returncode is None else "fail"
            )

            # Construct our "standardized" activity model for this command-line execution.
            string_args: list[str] = []
            for arg in process.args:
                string_args.append(str(arg))
            command_line_arguments: str = " ".join(string_args)
            completed_proc_model: StandardizedCompletedProcess = (
                StandardizedCompletedProcess(
                    process_execution_message, command_line_arguments, argv[0]
                )
            )
            completed_proc_model.pid = process.pid
            completed_proc_model.ppid = ppid
            completed_proc_model.stdin = stdin if stdin is not None else None
            completed_proc_model.stdout = process_stdout_result
            completed_proc_model.stderr = process_error_result
            completed_proc_model.return_code = returncode
            completed_proc_model.md5 = STDLib.get_md5(argv[0])

            return completed_proc_model
        except (
            subprocess.CalledProcessError,
            FileNotFoundError,
            PermissionError,
        ) as err:
            logger.error(err)


class DarwinSTDLib(STDLib):
    def __init__(self):
        super().__init__()

    @staticmethod
    def get_file_type(file_path: Path) -> str:
        """
        Attempts to get the "file type" of the specified file. To do this we use the `/usr/bin/file` LOLbin.
        """
        file_result = DarwinSTDLib.default_commandline_executer(
            ["/usr/bin/file", str(file_path)]
        )
        file_type: str = "UNKNOWN"
        if file_result.result == "success":
            if (
                file_result.stdout is not None
                and len(file_result.stdout.split(":")) > 0
            ):
                file_type = file_result.stdout.split(":")[1].strip()
        return file_type

    @staticmethod
    def make_file_executable(file_path: Path) -> bool:
        """
        Sets the executable bit for the specified file returning a boolean indication of success.
        """
        # Set the executable bit for the user
        execute_proc = subprocess.run(["chmod", "u+x", file_path], capture_output=True)
        if execute_proc.returncode != 0:
            return False
        return True

    @staticmethod
    def osacompile(
        script_path: Path, destination_path: Path, jxa: bool = False
    ) -> StandardizedCompletedProcess:
        """
        Python wrapper for the `/usr/bin/osascript` LoLBin. Executes either AppleScript or JXA scripts.
        """
        osacompile_bin_path: str = "/usr/bin/osacompile"
        if jxa:
            cmdl: list[str] = [
                osacompile_bin_path,
                "-l",
                "JavaScript",
                "-o",
                str(destination_path),
                str(script_path),
            ]
        else:
            cmdl: list[str] = [
                osacompile_bin_path,
                "-o",
                str(destination_path),
                str(script_path),
            ]

        return DarwinSTDLib.default_commandline_executer(cmdl)

    @staticmethod
    def compile_applescript(
        script_path: Path, destination_path: Path
    ) -> StandardizedCompletedProcess:
        """
        Wrapper for the osacompile method specifically for AppleScript.
        """
        return DarwinSTDLib.osacompile(script_path, destination_path)

    @staticmethod
    def compile_jxa(
        script_path: Path, destination_path: Path
    ) -> StandardizedCompletedProcess:
        """
        Wrapper for the osacompile method specifically for JXA.
        """
        return DarwinSTDLib.osacompile(script_path, destination_path, jxa=True)

    @staticmethod
    def osadecompile(
        script_path: Path, destination_path: Path | None = None
    ) -> StandardizedCompletedProcess:
        """
        Decompiles a specified OSA script byte-code file and returns the source in the stdout of the returned
        StandardizedCompletedProcess.
        """
        osadecompile_bin_path: str = "/usr/bin/osadecompile"

        cmdl: list = []
        if destination_path is not None:
            cmdl = [
                osadecompile_bin_path,
                "-o",
                str(destination_path),
                str(script_path),
            ]
        else:
            cmdl = [osadecompile_bin_path, str(script_path)]

        return DarwinSTDLib.default_commandline_executer(cmdl)

    @staticmethod
    def check_and_install_xc_cmdl_tools() -> bool:
        """
        Checks if the Xcode command line tools are installed. If not, it will prompt the user to install them.
        These tools are required to compile Swift.
        """
        # Check to ensure Xcode command line tools are installed
        xcode_select_bin_path: str = "/usr/bin/xcode-select"
        xcode_select_proc = DarwinSTDLib.default_commandline_executer(
            [xcode_select_bin_path, "-p"]
        )
        if "error: unable" in xcode_select_proc.stdout:
            # We need to install Xcode command line tools
            cmdl_install_proc = DarwinSTDLib.default_commandline_executer(
                [xcode_select_bin_path, "--install"]
            )
            install_rc: int = cmdl_install_proc.returncode
            install_stderr: str = cmdl_install_proc.stderr
            install_stdout: str = cmdl_install_proc.stdout

            if install_rc != 0 or len(install_stderr) > 0:
                print(
                    f"Unable to install Xcode command line tools!\nReturn code: {install_rc}\nSTDOUT: {install_stdout}\nSTDERR: {install_stderr}"
                )
                return False
            else:
                print("Xcode command line tools are now installed.")
                return True
        else:
            # Xcode command line tools were already installed!
            return True

    @staticmethod
    def compile_swift(
        source_path: Path, destination_path: Path
    ) -> StandardizedCompletedProcess:
        """
        Compiles a Swift source file at the provided path and outputs the Mach-O to the specified destination
        path. As a requirement, we first need to check if the Xcode command line tools are installed.
        """
        # `swiftc` is not a LOLBin, we'll need to install Xcode CMDL tools if not already
        if not DarwinSTDLib.check_and_install_xc_cmdl_tools():
            assert False, "Unable to install Xcode command line tools!"

        swiftc_bin_path: str = "/usr/bin/swiftc"
        cmdl: list = [swiftc_bin_path, source_path, "-o", destination_path]
        swift_compile_proc = subprocess.run(cmdl, capture_output=True)
        returncode: int = swift_compile_proc.returncode
        stdout: str = swift_compile_proc.stdout.decode("utf-8")
        stderr: str = swift_compile_proc.stderr.decode("utf-8")
        result: str = "success" if returncode == 0 else "failure"
        response_model: StandardizedCompletedProcess = StandardizedCompletedProcess(
            result=result, argv=str(cmdl), process_path=swiftc_bin_path
        )
        response_model.stdout = stdout
        response_model.stderr = stderr
        response_model.return_code = returncode

        return response_model

    @staticmethod
    def insert_plist_key(
        plist_path: Path, key: str, value_type: str, value: any
    ) -> bool:
        """
        Inserts a key / value pair into the specified property list file. Returning a boolean value indicating
        success / failure.

        Example:
        insert_plist_key("/Applications/Mail.app/Contents/Info.plist", "OSAAppletStayOpen", "-bool", "YES")
        """
        plutil_bin_path: str = "/usr/bin/plutil"
        cmdl: list = [
            plutil_bin_path,
            "-insert",
            key,
            value_type,
            value,
            str(plist_path),
        ]
        insert_proc = DarwinSTDLib.default_commandline_executer(cmdl)
        if "already exists" not in insert_proc.stdout and insert_proc.return_code != 0:
            return False

        return True

    @staticmethod
    def get_osa_script_from_xml(wflow_path: Path) -> str | None:
        """
        Given the path to an Applet's `document.wflow` we'll attempt to return the script text.
        If we were not able to find the script text then we'll return None.
        """
        if os.path.isfile(wflow_path):
            try:
                elements: list = (
                    ET.parse(wflow_path)
                    .getroot()
                    .findall("dict/array/dict/dict/dict/string")
                )
                for element in elements:
                    if element.text != "List":
                        return element.text
            except ET.ParseError:
                return None
        return None

    @staticmethod
    def get_osa_script_from_applet(applet_path: Path) -> str:
        """
        Given the path to an applet we'll attempt to retrieve the OSA script text. There are two cases to satisfy here:
        1. The script source will live in the `../Contents/document.wflow` XML document if made using Automator.app
        2. The script source will be located in `../Contents/Resources/Scripts/main.scpt` as a compiled OSA script
        3. Run-only script files --> not supported.
        """
        script_path: Path = applet_path.joinpath(
            "Contents", "Resources", "Scripts", "main.scpt"
        ).resolve()
        wflow_path: Path = applet_path.joinpath("Contents", "document.wflow").resolve()
        if os.path.isfile(wflow_path):
            # Automator case
            automator_script: str = DarwinSTDLib.get_osa_script_from_xml(wflow_path)
            return automator_script
        elif os.path.isfile(script_path):
            # `osacompile` / `Script Editor.app` case
            decompiled_script: str = DarwinSTDLib.osadecompile(script_path).stdout
            return decompiled_script
        else:
            # We were not able to find the script text for this applet.
            return ""

    @staticmethod
    def get_app_plist(app_path: Path) -> dict | None:
        """
        Attempts to return the specified app's Info.plist in dictionary form.
        """
        plist_path: Path = app_path.joinpath("Contents", "Info.plist")
        if os.path.isfile(plist_path):
            plutil: str = "/usr/bin/plutil"
            command_line: list = [plutil, "-convert", "json", plist_path, "-o", "-"]
            plist_json: str = subprocess.run(command_line, capture_output=True).stdout

            # Attempt to decode the plist json into a Python dictionary
            try:
                plist_data: dict = json.loads(plist_json)
                return plist_data
            except json.JSONDecodeError as jde:
                logging.error(f"JSON decode error: {jde}")
                return None
        else:
            return None


class LinuxSTDLib(STDLib):
    def __init__(self):
        super().__init__()
