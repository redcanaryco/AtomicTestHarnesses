from typing import List


def get_ascii_str(data: List[int], leftover: int = 16) -> str:
    """
    Turns a list of `int`s into an ascii string.

    If the `int` cannot be represented as an ascii character it prints a `.`
    """
    b: List[str] = []
    for i, c in enumerate(data):
        if leftover > 0 and i == leftover:
            break
        if 0x7E >= c >= 0x20:
            b.append(chr(c))
        else:
            b.append(".")

    ret = "".join(b)
    return ret


def hex_dump(data: bytes, width: int = 16, header: bool = True) -> None:
    """
    Print a hexump of the data.

    :param data: The data to print
    :param width: The number of bytes per line
    :param header: Whether or not to print the header line
    """
    if header:
        print(f"Offset    | ", end="")
        for i in range(width):
            print(f"{i:02x} ", end="")
        print("| Ascii")
        print(f"-" * ((width * 4) + 14))

    # Build the buffer to print
    size = width
    buff: List[List[int]] = []
    line = [0] * size
    for i, char in enumerate(data):
        if i % size == 0 and i != 0:
            buff.append(line)
            line = [0] * size
            line[0] = char
        else:
            line[i % size] = char

            if i == len(data) - 1:
                buff.append(line)

    # Calculate the leftovers
    num_lines = len(data) // width
    leftover = len(data) % width
    for i, line in enumerate(buff):
        print(f"{i*width:09X} | ", end="")
        if i == num_lines:
            for j in range(leftover):
                print(f"{line[j]:02x} ", end="")
            for j in range(width - leftover):
                print(f"   ", end="")
            print(f"| {get_ascii_str(line, leftover)}")
        else:
            for j in line:
                print(f"{j:02x} ", end="")
            print(f"| {get_ascii_str(line)}")


if __name__ == "__main__":
    """
    Just used for some testing
    """
    import os

    hex_dump(b"\x00")
    hex_dump(b"\x01\x01")
    hex_dump(b"\x03\x03\x03")
    hex_dump(b"\x03\x03\x03\x04")
    hex_dump(b"\x20\x21\x22\x23\x24")
    hex_dump(b"\x03\x03\x03\x04\x05\x06")
    hex_dump(b"\x03\x03\x03\x04\x05\x06\x07")
    hex_dump(b"\x00\x01\x02\x03\x04\x05\x06\x07")
    hex_dump(b"\x03\x03\x03\x04\x05\x06\x07\x08\x09")
    hex_dump(b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39")
    hex_dump(b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x40")
    hex_dump(b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x40\x41")
    hex_dump(b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x40\x41\x42")
    hex_dump(b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x40\x41\x42\x43")
    hex_dump(b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x40\x41\x42\x43\x44")
    hex_dump(b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x40\x41\x42\x43\x44\x45")
    hex_dump(os.urandom(16), width=6)
    hex_dump(os.urandom(32), width=7)
    hex_dump(os.urandom(37), width=8)
    hex_dump(os.urandom(127), width=9)
    hex_dump(os.urandom(320), header=False)
