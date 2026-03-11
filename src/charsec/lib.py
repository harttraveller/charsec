import builtins
import inspect
import textwrap
from dataclasses import dataclass
from pathlib import Path

# Unicode variation selectors: encode arbitrary bytes invisibly after a carrier character.
# VS1–VS16:   U+FE00–U+FE0F  → bytes 0–15
# VS17–VS256: U+E0100–U+E01EF → bytes 16–255

_VS_START = 0xFE00
_VS_END = 0xFE0F
_VSS_START = 0xE0100
_VSS_END = 0xE01EF


def _byte_to_vs(byte: int) -> str:
    if 0 <= byte < 16:
        return chr(_VS_START + byte)
    elif 16 <= byte < 256:
        return chr(_VSS_START + byte - 16)
    raise ValueError(f"byte must be 0-255, got {byte}")


def _vs_to_byte(cp: int) -> int | None:
    if _VS_START <= cp <= _VS_END:
        return cp - _VS_START
    elif _VSS_START <= cp <= _VSS_END:
        return cp - _VSS_START + 16
    return None


def encode(char: str, data: str | bytes) -> str:
    """
    Insert data into character.

    Args:
        char (str): A single character to encode hidden data into.
        data (str | bytes): The data to encode in the character.

    Returns:
        str: The character with data hidden in it as Unicode variation selectors.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return char + "".join(_byte_to_vs(b) for b in data)  # type: ignore


def decode(text: str) -> bytes:
    """
    Extract all hidden data from the input text.

    Args:
        text (str): The input text containing hidden data.

    Returns:
        bytes: The data hidden in the input text.
    """
    decoded: list[int] = []
    for char in text:
        byte = _vs_to_byte(ord(char))
        if byte is None:
            if decoded:
                break
        else:
            decoded.append(byte)
    return bytes(decoded)


def check(text: str) -> bool:
    """
    Check if the input text contains hidden data.

    Args:
        text (str): The input text.

    Returns:
        bool: `True` if the text contains at least one
            variation-selector byte, else `False`.
    """
    return any(_vs_to_byte(ord(c)) is not None for c in text)


def exec(code: str, debug: bool = True) -> None:
    hidden_code = decode(code).decode("utf-8")
    if len(hidden_code):
        if debug:
            print("[INFO] Found hidden code:\n\n")
            print(textwrap.indent(hidden_code, "    ") + "\n\n")
        builtins.exec(hidden_code)
    else:
        print("[INFO] Did not find hidden code.")


def run(file: str | Path, debug: bool = True) -> None:
    """
    Run the hidden code in the file provided.

    Args:
        file (str | Path): The path to the file to run.
        debug (bool): Whether to print out debug info.
    """
    if debug:
        print(f"[INFO] Reading source: {file}")
    with open(file, "r") as f:
        source_code = f.read()
    exec(source_code, debug)


def autorun(debug: bool = True) -> None:
    """
    This will run hidden code in whatever file it is called in.

    Args:
        debug (bool): Whether to print out debug info.
    """
    caller_frame = inspect.stack()[1]
    file = caller_frame.filename
    run(file, debug)


@dataclass
class ScanReport:
    """Report returned by :func:`scan`."""

    files_scanned: int
    """Total number of files examined."""

    files_with_hidden_data: list[Path]
    """Files that contain at least one hidden byte."""

    @property
    def found(self) -> bool:
        """``True`` if any hidden data was detected."""
        return len(self.files_with_hidden_data) > 0


def scan(
    path: str | Path,
    glob: str = "*",
    recursive: bool = True,
) -> ScanReport:
    """
    Scan a file or directory for hidden data.

    Args:
        path (str | Path): A file or directory to scan.  When *path* is a
            file, *glob* and *recursive* are ignored.
        glob (str): Glob pattern used to filter files when *path* is a
            directory.  Defaults to ``"*"`` (all files).
        recursive (bool): If ``True`` (the default), recurse into
            subdirectories.

    Returns:
        ScanReport: A report describing which files contain hidden data.
    """
    path = Path(path)
    if path.is_file():
        candidates = [path]
    else:
        candidates = [
            f
            for f in (path.rglob(glob) if recursive else path.glob(glob))
            if f.is_file()
        ]

    files_with_hidden_data: list[Path] = []
    for file in candidates:
        try:
            if check(file.read_text(encoding="utf-8")):
                files_with_hidden_data.append(file)
        except (OSError, UnicodeDecodeError):
            pass

    return ScanReport(
        files_scanned=len(candidates),
        files_with_hidden_data=files_with_hidden_data,
    )


def _strip_vs(text: str) -> str:
    """Return *text* with all variation-selector characters removed."""
    return "".join(c for c in text if _vs_to_byte(ord(c)) is None)


@dataclass
class RemoveReport:
    """Report returned by :func:`remove`."""

    files_processed: int
    """Total number of files examined."""

    files_modified: list[Path]
    """Files from which hidden data was stripped."""

    bytes_removed: int
    """Total number of hidden bytes removed across all modified files."""


def remove(
    path: str | Path,
    glob: str = "*",
    recursive: bool = True,
) -> RemoveReport:
    """
    Remove hidden data from a file or directory.

    Args:
        path (str | Path): A file or directory to clean.  When *path* is a
            file, *glob* and *recursive* are ignored.
        glob (str): Glob pattern used to filter files when *path* is a
            directory.  Defaults to ``"*"`` (all files).
        recursive (bool): If ``True`` (the default), recurse into
            subdirectories.

    Returns:
        RemoveReport: A report describing what was removed.
    """
    path = Path(path)
    if path.is_file():
        candidates = [path]
    else:
        candidates = [
            f
            for f in (path.rglob(glob) if recursive else path.glob(glob))
            if f.is_file()
        ]

    files_modified: list[Path] = []
    bytes_removed = 0
    for file in candidates:
        try:
            text = file.read_text(encoding="utf-8")
            if check(text):
                hidden = sum(1 for c in text if _vs_to_byte(ord(c)) is not None)
                file.write_text(_strip_vs(text), encoding="utf-8")
                files_modified.append(file)
                bytes_removed += hidden
        except (OSError, UnicodeDecodeError):
            pass

    return RemoveReport(
        files_processed=len(candidates),
        files_modified=files_modified,
        bytes_removed=bytes_removed,
    )


def inject(source: str | Path, target: str | Path) -> None:
    """
    Inject the data from the source file into the target file.
    The source file can be any format, but the target file must be a text file.

    Args:
        source (str | Path): The source file, eg: "meme.jpeg".
        target (str | Path): The target file, eg: "README.md".
    """
    with open(source, "rb") as f:
        binary = f.read()
    space = encode(" ", binary)
    with open(target, "r") as f:
        text = f.read()
    if check(text):
        raise OSError(f"File at {target} already contains hidden data.")
    newtext = text + space
    with open(target, "w") as f:
        f.write(newtext)


def extract(source: str | Path, target: str | Path) -> None:
    """
    Detect all hidden data in the source file and extract it to the target file.

    Args:
        source (str | Path): A source file, like "README.md".
        target (str | Path): A target file, like "output.jpeg".
    """
    with open(source, "r") as f:
        text = f.read()
    dec = decode(text)
    with open(target, "wb") as f:
        f.write(dec)
