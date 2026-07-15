"""Tests for the pure filtering logic behind --live (interactive live filtering)."""

from collections import deque

from logscope.parser import LogEntry
from logscope.viewer import (
    MAX_LIVE_BUFFER,
    LiveFilterState,
    _format_live_help_text,
    entry_passes_live_filters,
    filter_live_buffer,
)


def make_entry(level="INFO", message="something happened", service=None):
    raw = f"[{level}] {message}"
    return LogEntry(level=level, message=message, raw=raw, service=service)


def test_no_filters_passes_everything():
    state = LiveFilterState()
    entry = make_entry()
    assert entry_passes_live_filters(entry, state) is True


def test_hidden_level_is_excluded():
    state = LiveFilterState(hidden_levels={"DEBUG"})
    assert entry_passes_live_filters(make_entry(level="DEBUG"), state) is False
    assert entry_passes_live_filters(make_entry(level="INFO"), state) is True


def test_module_filter_matches_substring_case_insensitively():
    state = LiveFilterState(module="NET")
    assert entry_passes_live_filters(make_entry(service="netmod"), state) is True
    assert entry_passes_live_filters(make_entry(service="diskmod"), state) is False
    assert entry_passes_live_filters(make_entry(service=None), state) is False


def test_plain_search_matches_raw_line_case_insensitively():
    state = LiveFilterState(search="DISK")
    assert entry_passes_live_filters(make_entry(message="disk failure"), state) is True
    assert entry_passes_live_filters(make_entry(message="network ok"), state) is False


def test_regex_search_matches_pattern():
    state = LiveFilterState(search=r"fail(ure|ed)", use_regex=True)
    assert entry_passes_live_filters(make_entry(message="disk failure"), state) is True
    assert entry_passes_live_filters(make_entry(message="disk failed"), state) is True
    assert entry_passes_live_filters(make_entry(message="all good"), state) is False


def test_invalid_regex_does_not_hide_everything():
    """While the user is still typing a regex, an incomplete/invalid pattern
    shouldn't blank the whole view."""
    state = LiveFilterState(search="fail(", use_regex=True)
    assert entry_passes_live_filters(make_entry(message="disk failure"), state) is True


def test_filters_combine_with_and_semantics():
    state = LiveFilterState(module="net", search="error", hidden_levels={"DEBUG"})
    matching = make_entry(level="INFO", message="error seen", service="netmod")
    wrong_module = make_entry(level="INFO", message="error seen", service="diskmod")
    wrong_search = make_entry(level="INFO", message="all fine", service="netmod")
    wrong_level = make_entry(level="DEBUG", message="error seen", service="netmod")

    assert entry_passes_live_filters(matching, state) is True
    assert entry_passes_live_filters(wrong_module, state) is False
    assert entry_passes_live_filters(wrong_search, state) is False
    assert entry_passes_live_filters(wrong_level, state) is False


def test_filter_live_buffer_applies_over_whole_buffer():
    buffer = [
        (1, make_entry(level="INFO")),
        (2, make_entry(level="ERROR")),
        (3, make_entry(level="DEBUG")),
    ]
    state = LiveFilterState(hidden_levels={"DEBUG"})
    result = filter_live_buffer(buffer, state)
    assert [line_number for line_number, _ in result] == [1, 2]


def test_filter_live_buffer_is_retroactive_after_state_change():
    """Changing the filter must re-apply over entries buffered before the change."""
    buffer = [
        (1, make_entry(level="INFO", message="first")),
        (2, make_entry(level="INFO", message="second")),
    ]
    state = LiveFilterState()
    assert len(filter_live_buffer(buffer, state)) == 2

    state.search = "second"
    result = filter_live_buffer(buffer, state)
    assert len(result) == 1
    assert result[0][1].message == "second"


def test_live_buffer_deque_caps_at_max_size():
    """The buffer itself (a deque(maxlen=MAX_LIVE_BUFFER)) must silently evict
    the oldest entries once full, bounding memory during long --follow runs."""
    buf = deque(maxlen=MAX_LIVE_BUFFER)
    for i in range(MAX_LIVE_BUFFER + 500):
        buf.append((i, make_entry()))
    assert len(buf) == MAX_LIVE_BUFFER
    # Oldest 500 entries (line numbers 0..499) should have been evicted.
    assert buf[0][0] == 500


def test_describe_reports_active_filters():
    state = LiveFilterState()
    assert state.describe() == "no filters active"

    state = LiveFilterState(search="boot", use_regex=True, module="net", hidden_levels={"DEBUG", "INFO"})
    description = state.describe()
    assert "search[regex]='boot'" in description
    assert "module='net'" in description
    assert "hidden=DEBUG,INFO" in description


def test_help_text_grays_out_disabled_levels():
    """A hidden level's toggle label should be wrapped in dim markup so it
    visibly stands out as disabled; enabled ones stay plain."""
    state = LiveFilterState(hidden_levels={"DEBUG", "INFO"})
    text = _format_live_help_text(state)
    assert "[dim]1:DEBUG[/dim]" in text
    assert "[dim]2:INFO[/dim]" in text
    assert "3:WARN" in text and "[dim]3:WARN[/dim]" not in text


def test_help_text_has_no_dimmed_levels_when_nothing_hidden():
    state = LiveFilterState()
    text = _format_live_help_text(state)
    assert "[dim]1:DEBUG[/dim]" not in text
    assert "1:DEBUG" in text


def test_only_four_common_levels_are_toggleable():
    """TRACE/NOTICE/CRITICAL/ALERT/FATAL/UNKNOWN aren't offered for toggling
    in --live; only the everyday DEBUG/INFO/WARN/ERROR set is."""
    from logscope.viewer import LIVE_TOGGLE_LEVELS
    assert LIVE_TOGGLE_LEVELS == ["DEBUG", "INFO", "WARN", "ERROR"]
