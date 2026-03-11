from pathlib import Path

import charsec
import pytest

from charsec import RemoveReport, ScanReport, check, decode, encode, extract, inject, remove, scan
from charsec.lib import _byte_to_vs, _strip_vs, _vs_to_byte

EMOJI_LIST = [
    "😀",
    "😂",
    "🥰",
    "😎",
    "🤔",
    "👍",
    "👎",
    "👏",
    "😅",
    "🤝",
    "🎉",
    "🎂",
    "🍕",
    "🌈",
    "🌞",
    "🌙",
    "🔥",
    "💯",
    "🚀",
    "👀",
    "💀",
    "🥹",
]

ALPHABET_LIST = list("abcdefghijklmnopqrstuvwxyz")

TEXT_FIXTURES = [
    "Hello, World!",
    "Testing 123",
    "Special chars: !@#$%^&*()",
    "Unicode: 你好，世界",
    "",
    " ",
]


class TestVariationSelectorHelpers:
    def test_vs_block_boundaries(self):
        assert ord(_byte_to_vs(0)) == 0xFE00
        assert ord(_byte_to_vs(15)) == 0xFE0F

    def test_vss_block_boundaries(self):
        assert ord(_byte_to_vs(16)) == 0xE0100
        assert ord(_byte_to_vs(255)) == 0xE01EF

    def test_all_byte_values_round_trip(self):
        for b in range(256):
            vs = _byte_to_vs(b)
            assert _vs_to_byte(ord(vs)) == b

    def test_byte_to_vs_invalid(self):
        with pytest.raises((ValueError, Exception)):
            _byte_to_vs(256)
        with pytest.raises((ValueError, Exception)):
            _byte_to_vs(-1)

    def test_vs_to_byte_non_selector_returns_none(self):
        assert _vs_to_byte(ord("A")) is None
        assert _vs_to_byte(ord("😀")) is None
        assert _vs_to_byte(0x0000) is None


class TestEncode:
    def test_returns_string(self):
        assert isinstance(encode("😀", "hi"), str)

    def test_starts_with_carrier(self):
        for emoji in EMOJI_LIST:
            assert encode(emoji, "x").startswith(emoji)

    def test_str_and_bytes_equivalent(self):
        for text in TEXT_FIXTURES:
            assert encode("😀", text) == encode("😀", text.encode("utf-8"))

    def test_empty_payload_returns_carrier(self):
        assert encode("😀", "") == "😀"
        assert encode("😀", b"") == "😀"

    def test_all_byte_values(self):
        payload = bytes(range(256))
        encoded = encode("🔥", payload)
        assert encoded.startswith("🔥")
        assert decode(encoded) == payload

    def test_multi_char_carrier(self):
        encoded = encode("AB", "hello")
        assert encoded.startswith("AB")

    @pytest.mark.parametrize("emoji", EMOJI_LIST)
    @pytest.mark.parametrize("text", TEXT_FIXTURES)
    def test_roundtrip_all_emojis_and_texts(self, emoji: str, text: str):
        encoded = encode(emoji, text)
        assert decode(encoded).decode("utf-8") == text


class TestDecode:
    def test_returns_bytes(self):
        assert isinstance(decode(encode("😀", "hi")), bytes)

    def test_empty_payload(self):
        assert decode("😀") == b""

    def test_plain_text_no_selectors(self):
        assert decode("hello world") == b""

    def test_stops_at_first_non_selector_after_payload(self):
        encoded = encode("😀", "hi") + "extra"
        assert decode(encoded).decode("utf-8") == "hi"

    def test_raw_bytes_roundtrip(self):
        for b in range(256):
            assert decode(encode("x", bytes([b]))) == bytes([b])

    def test_unicode_text_roundtrip(self):
        texts = ["你好，世界", "こんにちは", "안녕하세요", "مرحبا"]
        for text in texts:
            assert decode(encode("🌍", text)).decode("utf-8") == text

    def test_long_payload(self):
        payload = "A" * 10_000
        assert decode(encode("🚀", payload)).decode("utf-8") == payload


class TestCheck:
    def test_encoded_string_detected(self):
        assert check(encode("😀", "secret"))

    def test_plain_emoji_not_detected(self):
        assert not check("😀")

    def test_plain_text_not_detected(self):
        assert not check("hello world")

    def test_empty_string_not_detected(self):
        assert not check("")

    def test_all_carriers_with_payload(self):
        for emoji in EMOJI_LIST:
            assert check(encode(emoji, "x"))

    def test_all_carriers_without_payload(self):
        for emoji in EMOJI_LIST:
            assert not check(emoji)

    @pytest.mark.parametrize("letter", ALPHABET_LIST)
    def test_alphabet_carriers_with_payload(self, letter: str):
        assert check(encode(letter, "data"))

    def test_empty_payload_not_detected(self):
        assert not check(encode("😀", ""))


# ---------------------------------------------------------------------------
# exec / run
# ---------------------------------------------------------------------------


class TestExec:
    def test_executes_hidden_code(self, capsys: pytest.CaptureFixture[str]):
        code = encode(" ", "print('hidden output')")
        charsec.exec(code, debug=False)
        assert "hidden output" in capsys.readouterr().out

    def test_no_hidden_code_message(self, capsys: pytest.CaptureFixture[str]):
        charsec.exec("plain text", debug=True)
        assert "Did not find hidden code" in capsys.readouterr().out

    def test_debug_prints_hidden_source(self, capsys: pytest.CaptureFixture[str]):
        code = encode(" ", "x = 42")
        charsec.exec(code, debug=True)
        assert "x = 42" in capsys.readouterr().out


class TestRun:
    def test_runs_hidden_code_from_file(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
        hidden = encode(" ", "print('run hidden')")
        f = tmp_path / "test.py"
        f.write_text(f"# comment{hidden}\n")
        charsec.run(f, debug=False)
        assert "run hidden" in capsys.readouterr().out

    def test_debug_prints_file_path(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
        f = tmp_path / "empty.py"
        f.write_text("# no hidden data")
        charsec.run(f, debug=True)
        assert str(f) in capsys.readouterr().out


# ---------------------------------------------------------------------------
# inject / extract
# ---------------------------------------------------------------------------


class TestInjectExtract:
    def test_basic_roundtrip(self, tmp_path: Path):
        source = tmp_path / "data.bin"
        target = tmp_path / "text.txt"
        payload = b"\x00\xff\x80hello"
        source.write_bytes(payload)
        target.write_text("some text content")
        inject(source, target)
        assert check(target.read_text())
        out = tmp_path / "out.bin"
        extract(target, out)
        assert out.read_bytes() == payload

    def test_inject_raises_if_already_has_hidden_data(self, tmp_path: Path):
        source = tmp_path / "data.bin"
        target = tmp_path / "text.txt"
        source.write_bytes(b"data")
        target.write_text(encode("x", "already here"))
        with pytest.raises(OSError):
            inject(source, target)

    def test_extract_writes_empty_bytes_if_no_hidden_data(self, tmp_path: Path):
        source = tmp_path / "plain.txt"
        target = tmp_path / "out.bin"
        source.write_text("nothing hidden")
        extract(source, target)
        assert target.read_bytes() == b""


# ---------------------------------------------------------------------------
# _strip_vs
# ---------------------------------------------------------------------------


class TestStripVs:
    def test_removes_all_variation_selectors(self):
        assert not check(_strip_vs(encode("x", "hello")))

    def test_preserves_carrier(self):
        assert _strip_vs(encode("x", "data")) == "x"

    def test_plain_text_unchanged(self):
        text = "Hello, World!"
        assert _strip_vs(text) == text

    def test_mixed_text(self):
        text = "before" + encode(" ", "hidden") + "after"
        assert _strip_vs(text) == "before after"


# ---------------------------------------------------------------------------
# ScanReport
# ---------------------------------------------------------------------------


class TestScanReport:
    def test_found_true_when_files_present(self):
        report = ScanReport(files_scanned=3, files_with_hidden_data=[Path("a.txt")])
        assert report.found is True

    def test_found_false_when_empty(self):
        report = ScanReport(files_scanned=3, files_with_hidden_data=[])
        assert report.found is False

    def test_fields(self):
        paths = [Path("x.txt"), Path("y.txt")]
        report = ScanReport(files_scanned=5, files_with_hidden_data=paths)
        assert report.files_scanned == 5
        assert report.files_with_hidden_data == paths


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


class TestScan:
    def test_single_file_with_hidden_data(self, tmp_path: Path):
        f = tmp_path / "a.txt"
        f.write_text(encode("x", "secret"))
        report = scan(f)
        assert report.files_scanned == 1
        assert f in report.files_with_hidden_data
        assert report.found

    def test_single_file_without_hidden_data(self, tmp_path: Path):
        f = tmp_path / "a.txt"
        f.write_text("plain text")
        report = scan(f)
        assert report.files_scanned == 1
        assert report.files_with_hidden_data == []
        assert not report.found

    def test_single_file_ignores_glob_and_recursive(self, tmp_path: Path):
        # When a file is passed directly, glob/recursive should have no effect
        f = tmp_path / "a.txt"
        f.write_text(encode("x", "secret"))
        report_default = scan(f)
        report_custom = scan(f, glob="*.py", recursive=False)
        assert report_default.files_scanned == report_custom.files_scanned == 1
        assert report_default.files_with_hidden_data == report_custom.files_with_hidden_data

    def test_directory_finds_dirty_files(self, tmp_path: Path):
        (tmp_path / "clean.txt").write_text("nothing here")
        (tmp_path / "dirty.txt").write_text(encode("😀", "hidden"))
        report = scan(tmp_path)
        assert report.files_scanned == 2
        assert tmp_path / "dirty.txt" in report.files_with_hidden_data
        assert tmp_path / "clean.txt" not in report.files_with_hidden_data

    def test_glob_filters_by_extension(self, tmp_path: Path):
        (tmp_path / "a.txt").write_text(encode("x", "a"))
        (tmp_path / "b.py").write_text(encode("x", "b"))
        report = scan(tmp_path, glob="*.txt")
        assert report.files_scanned == 1
        assert tmp_path / "a.txt" in report.files_with_hidden_data

    def test_recursive_scans_subdirs(self, tmp_path: Path):
        subdir = tmp_path / "sub"
        subdir.mkdir()
        (subdir / "nested.txt").write_text(encode("x", "nested"))
        report = scan(tmp_path, recursive=True)
        assert subdir / "nested.txt" in report.files_with_hidden_data

    def test_non_recursive_skips_subdirs(self, tmp_path: Path):
        subdir = tmp_path / "sub"
        subdir.mkdir()
        (subdir / "nested.txt").write_text(encode("x", "nested"))
        report = scan(tmp_path, recursive=False)
        assert subdir / "nested.txt" not in report.files_with_hidden_data

    def test_binary_files_skipped_gracefully(self, tmp_path: Path):
        (tmp_path / "binary.bin").write_bytes(bytes(range(256)))
        assert isinstance(scan(tmp_path), ScanReport)

    def test_returns_scan_report(self, tmp_path: Path):
        assert isinstance(scan(tmp_path), ScanReport)


# ---------------------------------------------------------------------------
# RemoveReport
# ---------------------------------------------------------------------------


class TestRemoveReport:
    def test_fields(self):
        paths = [Path("x.txt")]
        report = RemoveReport(files_processed=3, files_modified=paths, bytes_removed=10)
        assert report.files_processed == 3
        assert report.files_modified == paths
        assert report.bytes_removed == 10


# ---------------------------------------------------------------------------
# remove
# ---------------------------------------------------------------------------


class TestRemove:
    def test_removes_hidden_data_from_file(self, tmp_path: Path):
        f = tmp_path / "a.txt"
        f.write_text(encode("x", "secret"))
        report = remove(f)
        assert not check(f.read_text())
        assert f in report.files_modified
        assert report.bytes_removed > 0

    def test_plain_file_not_modified(self, tmp_path: Path):
        f = tmp_path / "plain.txt"
        original = "nothing hidden here"
        f.write_text(original)
        report = remove(f)
        assert f.read_text() == original
        assert f not in report.files_modified
        assert report.bytes_removed == 0

    def test_preserves_visible_text(self, tmp_path: Path):
        f = tmp_path / "a.txt"
        f.write_text("Hello world" + encode(" ", "hidden"))
        remove(f)
        assert f.read_text() == "Hello world "

    def test_single_file_ignores_glob_and_recursive(self, tmp_path: Path):
        # When a file is passed directly, glob/recursive should have no effect
        f = tmp_path / "a.txt"
        f.write_text(encode("x", "data"))
        report = remove(f, glob="*.py", recursive=False)
        assert not check(f.read_text())
        assert f in report.files_modified

    def test_directory_removes_all_dirty_files(self, tmp_path: Path):
        (tmp_path / "clean.txt").write_text("clean")
        (tmp_path / "dirty.txt").write_text(encode("😀", "payload"))
        report = remove(tmp_path)
        assert not check((tmp_path / "dirty.txt").read_text())
        assert tmp_path / "dirty.txt" in report.files_modified
        assert tmp_path / "clean.txt" not in report.files_modified

    def test_bytes_removed_matches_payload_length(self, tmp_path: Path):
        payload = b"hello"  # 5 bytes → 5 VS chars
        f = tmp_path / "a.txt"
        f.write_text(encode("x", payload))
        report = remove(f)
        assert report.bytes_removed == len(payload)

    def test_glob_filters_files(self, tmp_path: Path):
        (tmp_path / "a.txt").write_text(encode("x", "a"))
        (tmp_path / "b.py").write_text(encode("x", "b"))
        remove(tmp_path, glob="*.txt")
        assert not check((tmp_path / "a.txt").read_text())
        assert check((tmp_path / "b.py").read_text())

    def test_recursive_cleans_subdirs(self, tmp_path: Path):
        subdir = tmp_path / "sub"
        subdir.mkdir()
        (subdir / "nested.txt").write_text(encode("x", "nested"))
        remove(tmp_path, recursive=True)
        assert not check((subdir / "nested.txt").read_text())

    def test_non_recursive_skips_subdirs(self, tmp_path: Path):
        subdir = tmp_path / "sub"
        subdir.mkdir()
        nested = subdir / "nested.txt"
        nested.write_text(encode("x", "nested"))
        remove(tmp_path, recursive=False)
        assert check(nested.read_text())

    def test_returns_remove_report(self, tmp_path: Path):
        assert isinstance(remove(tmp_path), RemoveReport)

    def test_files_processed_count(self, tmp_path: Path):
        for i in range(3):
            (tmp_path / f"file{i}.txt").write_text("plain")
        report = remove(tmp_path)
        assert report.files_processed == 3

    def test_scan_then_remove_clears_all(self, tmp_path: Path):
        for i in range(3):
            (tmp_path / f"file{i}.txt").write_text(encode("x", f"secret{i}"))
        assert scan(tmp_path).found
        remove(tmp_path)
        assert not scan(tmp_path).found
