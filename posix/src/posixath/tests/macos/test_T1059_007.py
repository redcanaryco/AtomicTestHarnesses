import rich
import pytest
from pathlib import Path
import subprocess
import logging
import time
import psutil
import os
from os.path import abspath
import json
from inspect import getsourcefile

from ...utils.common import DarwinSTDLib
from ...utils.common import StandardizedCompletedProcess


# The following fixtures allow access to command line arguments
@pytest.fixture(scope="session")
def osascript_path(pytestconfig: pytest.Config):
    """
    The path to an uncompiled JXA script.
    """
    return pytestconfig.getoption("osascript_path")


@pytest.fixture(scope="session")
def osa_shell_path(pytestconfig: pytest.Config):
    """
    The path to a JXA shell script. E.g. `#!/usr/bin/osascript -l JavaScript`
    """
    return pytestconfig.getoption("osa_shell_path")


# Implements the Command and Scripting Interpreter: JavaScript (T1059.007) ATT&CK technique.
# Several variations are supported: OSAKit, osascript CMDL, shell scripts, applets, and stay-open-scripts.
@pytest.mark.macos
class TestJXA:
    __LIB_DIR = Path(abspath(getsourcefile(lambda: 0))).parent.joinpath(
        "library", "T1059_007"
    )
    __CHMOD_744: int = 0o744

    def test_osakit(self, osascript_path: Path):
        """
        Covers JavaScript for Automation (JXA) execution taking place throigh the OSAKit Foundation API (accessed
        through Swift).
        1. Compile Swift source into Mach-O
        2. Execute the Mach-O with arguments pointing to an AppleScript text source file.
        3. The binary will execute the JXA script via the OSAKit API
        One disadvantage of this method is the need for a valid code signature to satisfy Gatekeeper / AMFI. However,
        as can be seen here, Swift source files can be written to disk, compiled, and then signed adhoc.

        Arguments: `--osascript-path`

        EDR Detection:
        - Direct EDR detection is difficult here. At the most atomic level you're trying to detect
          a process reading arbitrary JXA and passing it to the OSAKit API via `executeAndReturnError`
          or `compileAndReturnError`. This behavior is not logged by any macOS EDR sensor to date.
        - You can infer OSA code execution by watching for ES_EVENT_TYPE_NOTIFY_MMAP events. Processes which map
          scripting additions / JavaScript / AppleScript components into memory are likely utilizing this API.
        """
        osakit_source_code_path: Path = self.__LIB_DIR.joinpath(
            "osakit_example.swift"
        ).resolve()
        script_path = (
            self.__LIB_DIR.joinpath("whoami_jxa.scpt").resolve()
            if osascript_path is None
            else osascript_path
        )
        if not os.path.isfile(osakit_source_code_path):
            assert False, "Swift source code file does not exist!"
        if not os.path.isfile(script_path):
            assert False, "Script does not exist!"

        # Load the JXA we're going to execute and execute the technique
        try:
            with open(script_path, "r") as script_dir_fd:
                jxa_source: str = " ".join(script_dir_fd.readlines())

            # Basic check to make sure we have a Swift source file
            if osakit_source_code_path.suffix != ".swift":
                logging.error("File is not Swift source code.")
                assert (
                    False
                ), f"This is not a valid Swift file: {osakit_source_code_path.name}"

            # Compile the Swift source file.
            destination_path: str = str(
                self.__LIB_DIR.joinpath("osakit_example").resolve()
            )
            swift_compile_result: StandardizedCompletedProcess = (
                DarwinSTDLib.compile_swift(osakit_source_code_path, destination_path)
            )
            # Check to make sure compilation was successful
            returncode: int = swift_compile_result.return_code
            stderr: str = swift_compile_result.stderr
            stdout: str = swift_compile_result.stdout
            if returncode != 0:
                assert False, f"Error compiling Swift source file: {stdout}\n{stderr}"

            # Check to ensure that this binary is executable...
            executable: bool = os.access(destination_path, self.__CHMOD_744)
            if not executable:
                # Set the executable bit for the user
                make_executable_result: bool = DarwinSTDLib.make_file_executable(
                    destination_path
                )
                if not make_executable_result:
                    assert False, "Failed to make the NSAppleScript example executable!"

            execution_result: dict = self.default_executer(
                [destination_path], str(script_path), jxa=jxa_source
            )

            # Pretty print the results
            rich.print_json(json.dumps(execution_result, indent=4, sort_keys=True))

            # Was it a success?
            assert (
                execution_result is not None and execution_result["result"] == "success"
            )
        except FileNotFoundError as fnfe:
            assert False, f"File not found:\n{fnfe}"

    def test_jxa_osascript_cmdl(self, osascript_path: Path):
        """
        Covers executing JXA scripts at the command line either through script load or through command line arguments.
        Both of the variations this test covers utilizes the `/usr/bin/osascript` LOLbin.
        1. Execute a JXA source file by passing its path
        2. Execute JXA source line-by-line using command line arguments

        Arguments: `--osascript-path`

        Note:
        In the future we could add support for the `-i` flag as well which enables interactive execution mode.

        EDR Detection:
        - Execution of the `osascript` binary will take place and any command line arguments will also be visible.
        - This is the most trivial case to detect.
        """
        script_path = (
            self.__LIB_DIR.joinpath("whoami_jxa.scpt").resolve()
            if osascript_path is None
            else osascript_path
        )
        osascript_bin_path = Path("/usr/bin/osascript")
        if not os.path.isfile(script_path):
            assert False, "Script does not exist!"

        whoami_cmdl = [
            osascript_bin_path,
            "-l",
            "JavaScript",
            "-e",
            "var app = Application.currentApplication();",
            "-e",
            "app.includeStandardAdditions = true;",
            "-e",
            "app.systemInfo().shortUserName;",
        ]

        try:
            # Try to load the JXA from the script file
            with open(script_path, "r") as script_dir_fd:
                jxa_source: str = " ".join(script_dir_fd.readlines())

            # Execute the script load variation
            execution_result: dict = self.default_executer(
                [osascript_bin_path, "-l", "JavaScript", str(script_path)],
                "",
                jxa=jxa_source,
            )

            # Pretty print the results
            rich.print_json(json.dumps(execution_result, indent=4, sort_keys=True))

            # Was it a success?
            assert (
                execution_result is not None and execution_result["result"] == "success"
            )

            # Execute the line-by-line variation
            cmdl_args_result: dict = self.default_executer(
                whoami_cmdl, "", jxa=jxa_source
            )

            # Pretty print the results from the command line arguments
            rich.print_json(json.dumps(cmdl_args_result, indent=4, sort_keys=True))

            # Was it a success?
            assert (
                cmdl_args_result is not None and cmdl_args_result["result"] == "success"
            )
        except FileNotFoundError as fnfe:
            assert False, f"File not found:\n{fnfe}"

    def test_jxa_shell_script(self, osa_shell_path: Path):
        """
        Covers the shell script execution variation in which the `osascript` binary can be invoked through the Unix
        shebang (`#!`). Unlike Mach-Os on macOS shell scripts cannot be code signed. Therefore, this presents a useful
        execution vector.

        Arguments: `--osa-shell-path`

        EDR Detection:
        - Execution of the `osascript` binary will take place and any command line arguments will also be visible.
        - The full script content on products supporting script loads
        """
        script_path: Path = (
            self.__LIB_DIR.joinpath("whoami_jxa.sh").resolve()
            if osa_shell_path is None
            else osa_shell_path
        )
        if not os.path.isfile(script_path):
            assert False, "Shell script does not exist!"

        # Check that it's a valid shell script
        file_check_result: str = DarwinSTDLib.get_file_type(script_path)
        shell_script_file_info: str = "JavaScript script text"

        if shell_script_file_info not in file_check_result:
            # We'll need to exit. The provided AppleScript is corrupted.
            assert False, f"{script_path}: is not a valid JXA file."

        # Set the executable bit for the user
        make_executable_result: bool = DarwinSTDLib.make_file_executable(script_path)
        if not make_executable_result:
            assert False, "Failed to make the OSAKit example executable!"

        # Load the JXA we're going to execute and execute the technique
        try:
            with open(script_path, "r") as script_fd:
                loaded_jxa: str = " ".join(script_fd.readlines()[1:])
            execution_result: dict = self.default_executer(
                [script_path], "", jxa=loaded_jxa
            )

            # Pretty print the results
            rich.print_json(json.dumps(execution_result, indent=4, sort_keys=True))

            # Was it a success?
            assert (
                execution_result is not None and execution_result["result"] == "success"
            )

        except FileNotFoundError as fnfe:
            assert False, f"File not found:\n{fnfe}"

    def test_jxa_applet(self, osascript_path: Path):
        """
        JXA code can also be executed in the form of an applet. Applets, fundamentally speaking are simply an
        application bundle, a thin Mach-O execution wrapper binary, and OSA script source (e.g. an JXA file).
        This makes them no different from other macOS apps. However, and by default when using the `/usr/bin/osacompile`
        binary the applet will be adhoc signed.

        Arguments: `--osascript-path`

        EDR Detection:
        - The executing binary name within the applet's `../Contents/MacOS/` directory will likely be named either:
          applet or Automator Application Stub (depending on how the applet was assembled).
        - The `/usr/bin/osascript` binary will likely not be observed in this case, unless explicitly invoked.
        - The OSA script source will be found in either applet's ../Contents/Resources/Scripts/ directory, or when
          built using Automator the source can be found withing `document.wflow`.
        - You can infer OSA code execution by watching for ES_EVENT_TYPE_NOTIFY_MMAP events. Processes which map
          scripting additions / JavaScript / AppleScript components into memory are applets
        """
        applet_source_path: Path = (
            self.__LIB_DIR.joinpath("whoami_jxa.scpt").resolve()
            if osascript_path is None
            else osascript_path
        )
        if not os.path.isfile(applet_source_path):
            assert False, "Script does not exist!"
        resulting_applet_path: Path = self.__LIB_DIR.joinpath(
            "example_jxa_applet.app"
        ).resolve()

        # Compile the JXA source into an applet.
        osacompile_proc = DarwinSTDLib.compile_jxa(
            applet_source_path, resulting_applet_path
        )
        if osacompile_proc.return_code != 0:
            assert False, "Error compiling the JXA applet!"

        # Load the JXA we're going to run and execute the technique
        loaded_jxa: str = DarwinSTDLib.get_osa_script_from_applet(resulting_applet_path)
        cmdl = ["/usr/bin/open", str(resulting_applet_path)]
        execution_result: dict = self.default_executer(cmdl, "", jxa=loaded_jxa)

        # Pretty print the results
        rich.print_json(json.dumps(execution_result, indent=4, sort_keys=True))

        # Was it a success?
        assert execution_result is not None and execution_result["result"] == "success"

    def test_jxa_stay_open_script(self, osascript_path: Path):
        """
        Stay-Open-Scripts are simply applets which generally have an idle handler and/or the `OSAAppletStayOpen`
        property list key set in their ../Contents/Info.plist file. Stay-Open-Scripts behave exactly as applets do
        with the nice side effect that they remain active actively running. Detection opportunities for
        stay-open-scripts are the same as those for applets.

        Arguments: `--osascript-path`
        """
        jxa_source_path: Path = (
            self.__LIB_DIR.joinpath("whoami_jxa.scpt")
            if osascript_path is None
            else osascript_path
        )
        if not os.path.isfile(jxa_source_path):
            assert False, "Script does not exist!"
        dest_applet_path: Path = self.__LIB_DIR.joinpath(
            "example_stay_open_jxa.app"
        ).resolve()

        # Compile the JXA source into an applet
        applet_proc: StandardizedCompletedProcess = DarwinSTDLib.compile_jxa(
            jxa_source_path, dest_applet_path
        )
        if applet_proc.return_code != 0 or len(applet_proc.stderr) > 0:
            assert False, "The stay-open-script did not properly execute."
        plist_path: Path = dest_applet_path.joinpath("Contents", "Info.plist").resolve()

        plist_result: bool = DarwinSTDLib.insert_plist_key(
            plist_path, key="OSAAppletStayOpen", value_type="-bool", value="YES"
        )
        if not plist_result:
            # If there was a problem inserting the stay open plist key
            assert (
                False
            ), f"Error adding Property List key: OSAAppletStayOpen to: {plist_path}"

        # Load the JXA we're going to execute and execute the technique
        loaded_jxa: str = DarwinSTDLib.get_osa_script_from_applet(dest_applet_path)
        cmdl = ["/usr/bin/open", str(dest_applet_path)]
        execution_result: StandardizedCompletedProcess = self.default_executer(
            argv=cmdl, stdin="", jxa=loaded_jxa
        )
        # Pretty print the results
        rich.print_json(json.dumps(execution_result, indent=4, sort_keys=True))

        # Was it a success?
        assert execution_result is not None and execution_result["result"] == "success"

    @staticmethod
    def default_executer(argv: list, stdin: str, jxa: str) -> dict | None:
        """
        A default command line executer for the JXA ATH pipeline. This executer handles the following
        functionality: `/usr/bin/osascript`, applet, shell script, and stay-open-script.
        1. `/usr/bin/osascript/`: Execute the specified JXA (either as a script load or as command line
           arguments).
        2. Launch Services via. `/usr/bin/open` which allows us to execute application bundles as the user would
           through the Dock or Finder. We use this method for applets and stay-open-scripts. The latter of which
           we also send a kill signal when we're finished. We correctly resolve pid and ppid when using the Launch
           Services method.
        3. Execution of scripts at the command line.
        """
        # Ensure we have all the information we need.
        if argv is None or len(argv) == 0:
            logging.debug(
                "There needs to be at least one command-line argument provided!"
            )
            return {"result": "failure"}
        try:
            # subprocess.run() is blocking which is why we need to use Popen here.
            proc: subprocess.Popen = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            # Save the PID -- NOTE: If the technique being executed is an Applet or Stay-Open-Script then this PID is
            # actually incorrect. We'll fix that below.
            pid: int = proc.pid
            ppid = psutil.Process(pid).ppid()

            # If there is user input that needs to be communicated to the process then do that now.
            process_stdout_result: str = ""
            if stdin is not None and len(stdin) > 0:
                # Save the STDOUT/STDERR from the process
                completed_process_result = proc.communicate(str(stdin))
                # Wait for the child process to terminate.
                proc.wait()
            else:
                # Otherwise we'll still want the STDOUT/STDERR from the executed technique
                completed_process_result = proc.communicate()

            process_stdout_result = completed_process_result[0]
            process_stderr_result = completed_process_result[1]

            # If required -- give the Apple Event Manager time to send / receive the AppleEvents.

            # Get the URI of the data we're interested in. Depending on the use case it'll be the following:
            # 1. The executing binary (e.g. `.app` for Applets, Stay-Open-Scripts, etc.)
            # 2. The executed script (e.g. `.sh` or `.scpt` for shell and OSA files respectively)
            executable_path: Path = argv[0]
            if argv[0] == Path("/usr/bin/osascript") and "-e" not in argv:
                if "-l" in argv:
                    executable_path = argv[3]

            # The following logic applies to Applet and stay-open-script application bundles specific test harness
            # execution
            if Path(executable_path).name == "open":
                # Save the .app's name.
                app_name: str = Path(argv[1]).name

                # Here we're going to get the name of the actual Mach-O binary being executed. These live in the .app's
                # "MacOS" directory.
                execution_dir: Path = (
                    Path(argv[1]).joinpath("Contents", "MacOS").resolve()
                )
                app_plist: dict = DarwinSTDLib.get_app_plist(Path(argv[1]))
                app_binary: str = ""
                if "CFBundleExecutable" in app_plist:
                    app_binary = app_plist["CFBundleExecutable"]
                else:
                    app_binary = os.listdir(execution_dir)[0]

                executable_path = (
                    Path(argv[1]).joinpath("Contents", "MacOS", app_binary).resolve()
                )

                # Using the `psutil` library we can get the correct pid for the executed application.
                # We will first try to find the application by the Mach-O binary name and then we will try with the
                # `.app` name.
                # If we still cannot find the pid of the executed binary then it's dead...
                app_proc_enumeration: list = list(
                    filter(lambda p: p.name() == app_name, psutil.process_iter())
                )
                if (
                    len(app_proc_enumeration) > 0
                    and app_proc_enumeration[0].pid is not None
                ):
                    pid = app_proc_enumeration[0].pid
                else:
                    app_proc_enumeration: list = list(
                        filter(
                            lambda p: p.name() == executable_path.stem,
                            psutil.process_iter(),
                        )
                    )
                    if (
                        len(app_proc_enumeration) > 0
                        and app_proc_enumeration[0].pid is not None
                    ):
                        pid = app_proc_enumeration[0].pid
                try:
                    ppid = psutil.Process(pid).ppid()
                except psutil.NoSuchProcess as err:
                    logging.warning(
                        "Could not find parent process of pid: {}\n{}".format(pid, err)
                    )
                    ppid = -1

                if len(app_proc_enumeration) > 0:
                    # This is mostly for Stay-Open-Scripts, but we're going to want to kill the process once we've
                    # collected all the necessary telemetry. For this we're going to use the 'kill' command.
                    time.sleep(1)
                    kill_status: subprocess.CompletedProcess = subprocess.run(
                        ["kill", f"{pid}"], capture_output=True
                    )
                    if kill_status.returncode == 1:
                        # Killing the process will most likely happen for Applets
                        logging.debug(
                            "Failed to kill process:\nProc Name: {}\nPID: {}".format(
                                executable_path.stem, pid
                            )
                        )

            returncode: int = proc.returncode
            process_error: bool = False
            if len(process_stdout_result) != 0 and not (
                "returned:OK" in process_stdout_result
                or "gaveUp:true" in process_stdout_result
            ):
                process_error = True
            if (
                Path.home().name in process_stdout_result
                or "NSAppleEvent" in process_stdout_result
            ):
                process_error = False

            # Fill out the completed process model
            completed_process = StandardizedCompletedProcess(
                result="success", argv=str(proc.args)
            )
            completed_process.attack_id = "T1059.007"
            completed_process.process_path = str(proc.args[0])
            completed_process.return_code = returncode
            completed_process.pid = pid
            completed_process.ppid = ppid
            completed_process.stdin = stdin
            completed_process.stdout = process_stdout_result
            completed_process.executable_name = Path(executable_path).name
            completed_process.md5 = DarwinSTDLib.get_md5(executable_path)
            completed_process.executed_jxa = jxa if len(jxa) > 0 else ""

            if returncode != 0 or process_error:
                completed_process.result = "failure"
            return completed_process.__dict__
        except (
            subprocess.CalledProcessError,
            FileNotFoundError,
            PermissionError,
        ) as err:
            assert False, f"Failure: {err}"
