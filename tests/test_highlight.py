"""Tests for custom keyword highlighting feature."""

from logscope.viewer import manager
from logscope.parser import LogEntry


def test_format_log_without_highlight():
    """Log formatting without highlight should work normally."""
    entry = LogEntry(level="INFO", message="System started", raw="[INFO] System started")
    text = manager.format_log(entry, line_number=None, highlight=None)
    assert "System started" in text.plain


def _message_style(text):
    """Return the style applied to the message portion (last span)."""
    return text.spans[-1].style


def test_format_log_message_matches_level_color():
    """The message should render in the same style as its level's icon/label,
    except INFO and DEBUG which get their own dedicated treatment."""
    manager.apply_theme("default", no_color=False)
    for level in ("ERROR", "WARN", "CRITICAL", "NOTICE"):
        entry = LogEntry(level=level, message="something happened", raw=f"[{level}] something happened")
        text = manager.format_log(entry, line_number=None)
        expected_style = manager.level_mapping[level][1]
        assert _message_style(text) == expected_style


def test_format_log_info_message_is_soft_white():
    manager.apply_theme("default", no_color=False)
    entry = LogEntry(level="INFO", message="System started", raw="[INFO] System started")
    text = manager.format_log(entry, line_number=None)
    assert _message_style(text) == "white"


def test_format_log_debug_message_stays_dim():
    """DEBUG keeps the plain gray the message used to render in for every level."""
    manager.apply_theme("default", no_color=False)
    entry = LogEntry(level="DEBUG", message="opening connection", raw="[DEBUG] opening connection")
    text = manager.format_log(entry, line_number=None)
    assert _message_style(text) == "dim"


def test_format_log_renders_data_bytes_below_message():
    """A DATA[..] byte dump should render on its own line(s) below the message,
    wrapped at 16 bytes per row."""
    entry = LogEntry(
        level="INFO",
        message="The factorial of 10 = 0x12f",
        raw="[00:00:06.900,573] <inf> Less4_Exer2: The factorial of 10 = 0x12f DATA[..]",
        data_bytes=[
            "12", "34", "56", "78", "90", "a1", "b2", "c3",
            "d4", "e5", "f6", "ff", "ff", "ff", "ee", "ab", "ab", "ab",
        ],
    )
    text = manager.format_log(entry, line_number=None)
    lines = text.plain.split("\n")
    assert lines[0].endswith("The factorial of 10 = 0x12f")
    assert "DATA:" in lines[1]
    assert "12 34 56 78 90 a1 b2 c3 d4 e5 f6 ff ff ff ee ab" in lines[1]
    assert lines[2].strip() == "ab ab"


def test_format_log_renders_data_bytes_without_separator_when_source_had_none():
    """If the DATA[..] segment had no spaces between bytes, the rendered dump
    shouldn't insert any either."""
    entry = LogEntry(
        level="INFO",
        message="msg",
        raw="[00:00:06.900,573] <inf> Less4_Exer2: msg DATA[..]",
        data_bytes=["12", "34", "56", "78"],
        data_bytes_spaced=False,
    )
    text = manager.format_log(entry, line_number=None)
    lines = text.plain.split("\n")
    assert "12345678" in lines[1]
    assert "12 34 56 78" not in lines[1]


def test_format_log_without_data_bytes_has_no_extra_lines():
    entry = LogEntry(level="INFO", message="no payload here", raw="[INFO] no payload here")
    text = manager.format_log(entry, line_number=None)
    assert "\n" not in text.plain


def test_format_log_no_wrapping_by_default():
    """Without an explicit wrap width, long messages stay on a single line."""
    long_message = "word " * 40
    entry = LogEntry(level="INFO", message=long_message.strip(), raw="[INFO] " + long_message)
    text = manager.format_log(entry, line_number=None)
    assert "\n" not in text.plain


def test_format_log_wraps_long_message_with_indented_continuation():
    """A message exceeding --wrap-width should wrap onto indented continuation
    lines that line up under where the message started."""
    entry = LogEntry(
        level="INFO",
        message="this message is definitely too long to fit on one short line",
        raw="[INFO] this message is definitely too long to fit on one short line",
    )
    try:
        manager.apply_theme("default")
        manager.set_wrap_width(40)
        text = manager.format_log(entry, line_number=None)
        lines = text.plain.split("\n")
        assert len(lines) > 1
        assert all(len(line) <= 40 for line in lines)

        first_word = entry.message.split()[0]
        prefix_width = lines[0].index(first_word)
        for continuation in lines[1:]:
            assert continuation[:prefix_width].strip() == ""
            assert not continuation.startswith(" " * (prefix_width + 1))

        reconstructed = " ".join(
            [lines[0][prefix_width:]] + [line.strip() for line in lines[1:]]
        )
        assert reconstructed == entry.message
    finally:
        manager.set_wrap_width(None)


def test_format_log_wraps_data_dump_rows_to_wrap_width():
    """The DATA[..] hex dump should also wrap its rows to fit --wrap-width,
    instead of the fixed 16-bytes-per-row default."""
    entry = LogEntry(
        level="INFO",
        message="short",
        raw="[INFO] short DATA[..]",
        data_bytes=["12", "34", "56", "78", "90", "a1", "b2", "c3"],
    )
    try:
        manager.apply_theme("default")
        manager.set_wrap_width(30)
        text = manager.format_log(entry, line_number=None)
        lines = text.plain.split("\n")
        data_lines = [line for line in lines if line.strip() and "short" not in line]
        assert len(data_lines) > 1
        assert all(len(line) <= 30 for line in data_lines)
    finally:
        manager.set_wrap_width(None)


def test_format_log_left_aligns_when_theme_has_no_icons():
    """A theme where no level carries an icon should skip the icon column entirely."""
    no_icon_theme = {
        "levels": {"INFO": ("", "bold green"), "UNKNOWN": ("", "dim white")},
        "highlights": {},
    }
    entry = LogEntry(level="INFO", message="System started", raw="[INFO] System started")
    try:
        manager.apply_theme(no_icon_theme)
        text = manager.format_log(entry, line_number=None)
        assert text.plain == "INFO    System started"
    finally:
        manager.apply_theme("default")


def test_simple_theme_has_no_icons_and_left_aligns():
    """The built-in 'simple' theme ships with no emojis and should left-align levels."""
    entry = LogEntry(level="ERROR", message="Database timeout", raw="[ERROR] Database timeout")
    try:
        manager.apply_theme("simple")
        assert not manager._has_icons
        text = manager.format_log(entry, line_number=None)
        assert text.plain == "ERROR   Database timeout"
    finally:
        manager.apply_theme("default")


def test_format_log_shows_zephyr_timestamp_and_module():
    """Zephyr entries should render their timestamp and module before the message."""
    entry = LogEntry(
        level="INFO",
        message="The factorial of  1 = 1",
        raw="[00:00:06.900,512] <inf> Less4_Exer2: The factorial of  1 = 1",
        service="Less4_Exer2",
        timestamp_text="[00:00:06.900,512]",
    )
    text = manager.format_log(entry, line_number=None)
    assert "[00:00:06.900,512]" in text.plain
    assert "Less4_Exer2" in text.plain
    assert "Less4_Exer2:" not in text.plain
    assert "The factorial of  1 = 1" in text.plain


def test_format_log_pads_shorter_timestamp_and_module_to_keep_message_aligned():
    """A shorter timestamp/module (e.g. from a dropped UART byte) should be
    space-padded to the widest one seen so far, so the message column doesn't
    shift left relative to other lines in the same stream."""
    try:
        manager.apply_theme("default")
        wide_entry = LogEntry(
            level="INFO",
            message="first",
            raw="[00:00:06.900,512] <inf> Less4_Exer2: first",
            service="Less4_Exer2",
            timestamp_text="[00:00:06.900,512]",
        )
        narrow_entry = LogEntry(
            level="INFO",
            message="second",
            raw="[00:00:07] <inf> mod: second",
            service="mod",
            timestamp_text="[00:00:07]",
        )
        wide_text = manager.format_log(wide_entry, line_number=None)
        narrow_text = manager.format_log(narrow_entry, line_number=None)

        message_column = wide_text.plain.index("first")
        assert narrow_text.plain.index("second") == message_column
    finally:
        manager.apply_theme("default")


def test_format_log_with_highlight():
    """Highlight keyword should be present in formatted output."""
    entry = LogEntry(level="ERROR", message="Payment failed for user", raw="[ERROR] Payment failed for user")
    text = manager.format_log(entry, line_number=None, highlight="Payment", highlight_color="bold magenta")
    # The formatted text should contain the message
    assert "Payment" in text.plain
    assert "failed for user" in text.plain


def test_format_log_with_line_numbers_and_highlight():
    """Both line numbers and highlight should work together."""
    entry = LogEntry(level="WARN", message="Database connection timeout", raw="[WARN] Database connection timeout")
    text = manager.format_log(entry, line_number=42, highlight="timeout", highlight_color="bold red")
    assert "42" in text.plain
    assert "timeout" in text.plain


def test_format_log_highlight_case_sensitive():
    """Highlight should be case-sensitive for matching."""
    entry = LogEntry(level="INFO", message="Processing PAYMENT transaction", raw="[INFO] Processing PAYMENT transaction")
    text = manager.format_log(entry, line_number=None, highlight="payment", highlight_color="bold green")
    # Since split is case-sensitive, "PAYMENT" won't match "payment"
    # but the message should still be there
    assert "Processing" in text.plain
    assert "PAYMENT" in text.plain


def test_format_log_highlight_empty_keyword():
    """Empty highlight keyword should not affect formatting."""
    entry = LogEntry(level="DEBUG", message="Debug message here", raw="[DEBUG] Debug message here")
    text = manager.format_log(entry, line_number=None, highlight="", highlight_color="bold cyan")
    # Empty string highlight should not cause issues
    assert "Debug message here" in text.plain


def test_format_log_highlight_not_in_message():
    """Keyword not present in message should still render fine."""
    entry = LogEntry(level="INFO", message="User logged in", raw="[INFO] User logged in")
    text = manager.format_log(entry, line_number=None, highlight="payment", highlight_color="bold yellow")
    assert "User logged in" in text.plain


def test_format_log_multiple_occurrences():
    """Highlight should work with multiple occurrences of keyword."""
    entry = LogEntry(level="ERROR", message="Payment failed, retry Payment now", raw="[ERROR] Payment failed, retry Payment now")
    text = manager.format_log(entry, line_number=None, highlight="Payment", highlight_color="bold red")
    # Both occurrences should be present
    assert text.plain.count("Payment") == 2
