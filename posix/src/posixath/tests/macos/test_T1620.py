import json
import time
import os
import rich
import math
import pytest
from inspect import getsourcefile
from os.path import abspath
from pathlib import Path
import re
from ...utils.common import STDLib, DarwinSTDLib
from ...utils.common import StandardizedCompletedProcess


# The following fixtures allow access to command line arguments
@pytest.fixture(scope="session")
def bundle_path(pytestconfig: pytest.Config):
    """
    The path to the bundle to reflectively load.
    """
    return pytestconfig.getoption("bundle_path")


@pytest.fixture(scope="session")
def source_code_path(pytestconfig: pytest.Config):
    """
    The path to a C source code file to compile into a bindle.
    """
    return pytestconfig.getoption("source_code_path")


@pytest.mark.macos
class TestReflectiveLoading:
    # Path to the library directory containing supporting resources for this AtomicTestHarness execution.
    __LIB_DIR = Path(abspath(getsourcefile(lambda: 0))).parent.joinpath(
        "library", "T1620"
    )
    __CHMOD_744: int = 0o744

    def test_nscreateobjectfileimagefrommemory(
        self, bundle_path: Path = None, source_code_path: Path = None
    ) -> None:
        """
        Tests T1620: Reflective Code loading by using `NSCreateObjectFileImageFromMemory` to reflectively load a bundle. A default implementation is provided, but you may also provide your own C source code or your own bundle to reflectively load.

        Arguments: `--bundle-path` or `--source-code-path`

        EDR detection (specific to NSCreateObjectFileImageFromMemory):
        - The bundle's image will be written to disk at a temporary location as a defense mitation by Apple. This file will be at: `/private/var/folders/.../NSCreateObjectFileImageFromMemory-...` and is logged in our results as `nslinkmodule_writeback_path`.
        - Additionally, the AUL (Apple Unified Log) will also contain references to this file write occuring.
        """
        # No options provided. We'll use our default `hello.c` code.
        default_dylib_code: Path = self.__LIB_DIR.joinpath("hello.c").resolve()
        libHello_path: Path = self.__LIB_DIR.joinpath("libHello.bundle").resolve()
        if source_code_path is not None:
            default_dylib_code = source_code_path
        if bundle_path is not None:
            libHello_path = bundle_path
        else:
            options: list = ["-bundle"]
            c_compile_result: StandardizedCompletedProcess = (
                DarwinSTDLib.gcc_compile_with_options(
                    default_dylib_code, libHello_path, options
                )
            )
            # Check to make sure compilation was successful
            returncode: int = c_compile_result.return_code
            stderr: str = c_compile_result.stderr
            stdout: str = c_compile_result.stdout
            if returncode != 0:
                assert False, f"Error compiling C source file: {stdout}\n{stderr}"

        # Now we have our dylib. Let's compile our `nscreateobjectfileimagefrommemory.c` code.
        nscreateobjectfileimagefrommemory_reflector_code: Path = (
            self.__LIB_DIR.joinpath("nscreateobjectfileimagefrommemory.c").resolve()
        )
        nscreateobjectfileimagefrommemory_path: Path = self.__LIB_DIR.joinpath(
            "nscreateobjectfileimagefrommemory"
        ).resolve()
        c_compile_result: StandardizedCompletedProcess = (
            DarwinSTDLib.gcc_compile_with_options(
                nscreateobjectfileimagefrommemory_reflector_code,
                nscreateobjectfileimagefrommemory_path,
            )
        )
        # Check to make sure compilation was successful
        returncode: int = c_compile_result.return_code
        stderr: str = c_compile_result.stderr
        stdout: str = c_compile_result.stdout
        if returncode != 0:
            assert False, f"Error compiling C source file: {stdout}\n{stderr}"
        # Check to ensure that this binary is executable...
        executable: bool = os.access(
            nscreateobjectfileimagefrommemory_path, self.__CHMOD_744
        )
        if not executable:
            # Set the executable bit for the user
            if not DarwinSTDLib.make_file_executable(
                nscreateobjectfileimagefrommemory_path
            ):
                assert (
                    False
                ), "Failed to make the nscreateobjectfileimagefrommemory.c executable!"

        # Record how long this takes as we'll use it for lookback context
        start_time = time.time()
        arguments = [
            str(nscreateobjectfileimagefrommemory_path.resolve()),
            str(libHello_path),
        ]
        execution_result = DarwinSTDLib.default_commandline_executer(arguments)
        elapsed_time = math.ceil(time.time() - start_time)
        elapsed_time = 2 if elapsed_time < 1 else elapsed_time

        # Query the log for the NSLinkModule writeback path
        options = ["--style", "compact"]
        predicate = "eventMessage CONTAINS 'NSCreateObjectFileImageFromMemory-'"
        logs = DarwinSTDLib.query_aul(options, predicate, look_back_s=elapsed_time)
        filtered_logs = [
            log
            for log in logs
            if "kernel" in log and "(AppleMobileFileIntegrity) AMFI" in log
        ]
        extracted_path: str = "NOT FOUND"
        if filtered_logs is not None and len(filtered_logs) > 0:
            path_pattern = re.compile(
                r"(/private/var/folders/.+?/NSCreateObjectFileImageFromMemory-[^\s']+)"
            )
            most_recent_log = filtered_logs[-1]
            extracted_path = (
                path_pattern.search(most_recent_log).group(1)
                if path_pattern.search(most_recent_log)
                else None
            )

        # Inject our context and results
        results_json = execution_result.to_json(sort_keys=True, indent=4)
        results_dict: dict = json.loads(results_json)
        results_dict["attack_id"] = "T1620"
        results_dict["nslinkmodule_writeback_path"] = extracted_path
        results_json = json.dumps(results_dict, sort_keys=True, indent=4)

        rich.print_json(results_json)

        # Was it a success?
        assert results_dict is not None and results_dict["result"] == "success"
