import shutil
from ...utils.common import STDLib
from hashlib import md5
from pathlib import Path


class TestSTDLib:
    def test_get_executable_md5(self, tmp_path: Path):
        content = b"Get To the Chopper!"
        f = tmp_path / "durp.txt"
        f.write_bytes(content)

        ls_full_path = shutil.which("ls")
        assert ls_full_path is not None

        ls_data = Path(ls_full_path).read_bytes()

        # This is just a normal file
        assert None == STDLib.get_executable_md5(f)

        # This is a system exectuable
        assert md5(ls_data).hexdigest() == STDLib.get_executable_md5(Path("ls"))

    def test_get_username(self):
        pass

    def test_default_commandline_executor(self):
        pass
