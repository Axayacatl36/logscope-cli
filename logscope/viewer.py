import os
import re
import select
import sys
import textwrap
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime
from typing import Deque, Iterable, Iterator, List, Optional, Pattern, Set, TextIO, Tuple

from rich.console import Console, Group
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.highlighter import RegexHighlighter
from rich.markup import escape as rich_escape
from rich.theme import Theme

from .parser import parse_line, LogEntry, _normalize_level
from .themes import DEFAULT_THEMES

try:
    import termios
    import tty
    _RAW_TERMINAL_SUPPORTED = True
except ImportError:  # pragma: no cover - Windows has no termios/tty
    _RAW_TERMINAL_SUPPORTED = False

# Level severity order (lowest to highest)
# Used for --min-level threshold filtering
LEVEL_ORDER = {
    "TRACE": 0,
    "DEBUG": 1,
    "INFO": 2,
    "NOTICE": 3,
    "WARN": 4,
    "ERROR": 5,
    "CRITICAL": 6,
    "ALERT": 7,
    "FATAL": 8,
    "UNKNOWN": 0,  # Treat as lowest
}

# --- Live filtering (--live) -------------------------------------------------
# Bounded so a long-running --follow session can't grow memory without limit;
# filters are re-applied over this whole buffer whenever they change, which at
# this size is effectively instant (no need for anything fancier/incremental).
MAX_LIVE_BUFFER = 2000
MAX_LIVE_VISIBLE_LOGS = 25

# Number keys used to toggle each level's visibility on/off, shown in the help bar.
# Only the four everyday levels are toggleable in --live; TRACE/NOTICE/CRITICAL/
# ALERT/FATAL/UNKNOWN entries are always shown and can't be hidden this way.
LIVE_TOGGLE_LEVELS = ["DEBUG", "INFO", "WARN", "ERROR"]
LIVE_LEVEL_KEYS = "1234"
LEVEL_KEY_BY_LEVEL = dict(zip(LIVE_TOGGLE_LEVELS, LIVE_LEVEL_KEYS))
LEVEL_BY_KEY = dict(zip(LIVE_LEVEL_KEYS, LIVE_TOGGLE_LEVELS))


@dataclass
class LiveFilterState:
    """Adjustable filter state for --live mode. Mutated in place by keyboard
    commands and re-applied over the whole buffer on every change."""
    search: Optional[str] = None
    use_regex: bool = False
    hidden_modules: Set[str] = field(default_factory=set)
    hidden_levels: Set[str] = field(default_factory=set)

    def describe(self) -> str:
        parts = []
        if self.search:
            kind = "regex" if self.use_regex else "text"
            parts.append(f"search[{kind}]='{self.search}'")
        if self.hidden_modules:
            parts.append("hidden modules=" + ",".join(sorted(self.hidden_modules)))
        if self.hidden_levels:
            ordered = sorted(self.hidden_levels, key=LIVE_TOGGLE_LEVELS.index)
            parts.append("hidden=" + ",".join(ordered))
        return " | ".join(parts) if parts else "no filters active"


def entry_passes_live_filters(entry: LogEntry, state: LiveFilterState) -> bool:
    """Pure predicate: does this entry pass the current live filter state?"""
    if entry.level in state.hidden_levels:
        return False

    if entry.service and entry.service in state.hidden_modules:
        return False

    if state.search:
        if state.use_regex:
            try:
                pattern = re.compile(state.search, re.IGNORECASE)
            except re.error:
                # Invalid/incomplete regex (likely still being typed) - don't hide everything.
                return True
            if not pattern.search(entry.raw):
                return False
        elif state.search.lower() not in entry.raw.lower():
            return False

    return True


def filter_live_buffer(
    buffer: Iterable[Tuple[int, LogEntry]], state: LiveFilterState
) -> List[Tuple[int, LogEntry]]:
    """Apply the live filter state to every entry currently in the buffer."""
    return [(line_number, entry) for line_number, entry in buffer if entry_passes_live_filters(entry, state)]


@dataclass
class ModulePickerState:
    """State for the interactive multi-select module list (opened with 'm' in
    --live). `modules` is a snapshot taken when the picker opens; `hidden` is
    mutated as the user toggles rows."""
    modules: List[str]
    hidden: Set[str] = field(default_factory=set)
    cursor: int = 0

    def move(self, delta: int) -> None:
        if self.modules:
            self.cursor = (self.cursor + delta) % len(self.modules)

    def toggle_current(self) -> None:
        if not self.modules:
            return
        name = self.modules[self.cursor]
        if name in self.hidden:
            self.hidden.discard(name)
        else:
            self.hidden.add(name)

    def toggle_all(self) -> None:
        """Hide everything if anything is currently shown; otherwise show everything."""
        if len(self.hidden) < len(self.modules):
            self.hidden = set(self.modules)
        else:
            self.hidden = set()


def _format_module_picker(picker: ModulePickerState, wrap_width: Optional[int] = None) -> str:
    """Render the module picker as a list, marking the cursor row and graying
    out deselected (hidden) modules. Long module names wrap to an indented
    continuation line once `wrap_width` is set, same as messages/DATA dumps."""
    if not picker.modules:
        return "[dim](no modules seen yet)[/dim]"
    lines = []
    for i, name in enumerate(picker.modules):
        marker = "[ ]" if name in picker.hidden else "[x]"
        cursor = "→ " if i == picker.cursor else "  "
        prefix = f"{cursor}{marker} "

        if wrap_width and wrap_width > 0:
            available = max(wrap_width - len(prefix), 10)
            chunks = textwrap.wrap(name, width=available) or [""]
        else:
            chunks = [name]

        indent = " " * len(prefix)
        for j, chunk in enumerate(chunks):
            row_prefix = prefix if j == 0 else indent
            # Escape the whole line (marker brackets included) since Rich would
            # otherwise try to parse "[x]"/"[ ]" as markup tags and swallow them.
            label = rich_escape(f"{row_prefix}{chunk}")
            if name in picker.hidden:
                label = f"[dim]{label}[/dim]"
            lines.append(label)
    return "\n".join(lines)


if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

class LogScopeHighlighter(RegexHighlighter):
    """Apply style to anything that looks like an IP address, URL, or timestamp."""
    base_style = "logscope."
    highlights = [
        r"(?P<ip>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)",
        r"(?P<url>https?://[a-zA-Z0-9./?=#_%:-]+)",
        r"(?P<timestamp>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)",
        r"(?P<uuid>\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b)",
        r"(?P<email>\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b)",
        r"(?P<path>(?:[a-zA-Z]:|\/)[a-zA-Z0-9._\-\/\\ ]+)",
        r"(?P<status_ok>\b(200|201|204)\b)",
        r"(?P<status_warn>\b(301|302|400|401|403|404)\b)",
        r"(?P<status_err>\b(500|502|503|504)\b)",
        r"(?P<method>\b(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\b)",
    ]


_DATA_BYTES_PER_ROW = 16


class LogScopeManager:
    """Manages the console state and current theme."""
    def __init__(self, theme_name: str = "default"):
        self._no_color = False
        # Max total line width before the message/DATA dump wraps to an indented
        # continuation line. None (the default) disables wrapping entirely.
        self._wrap_width: Optional[int] = None
        self.apply_theme(theme_name)

    def set_wrap_width(self, width: Optional[int]) -> None:
        """Set the max line width for message/DATA wrapping; None disables it."""
        self._wrap_width = width

    def apply_theme(self, theme_name_or_dict, no_color: bool = False, custom_themes: Optional[dict] = None):
        self._no_color = no_color
        themes = custom_themes if custom_themes is not None else DEFAULT_THEMES
        if isinstance(theme_name_or_dict, str):
            theme_config = themes.get(theme_name_or_dict, themes["default"])
        else:
            theme_config = theme_name_or_dict

        self.level_mapping = theme_config["levels"]
        # If no level in this theme carries an actual icon, drop the icon column
        # entirely instead of padding for it, so level names stay left-aligned.
        self._has_icons = any(icon.strip() for icon, _ in self.level_mapping.values())
        # Widest timestamp/module text seen so far this session. A corrupted line
        # (e.g. a dropped UART byte shrinking "[00:00:06.900,512]" by a char) still
        # gets padded out to this width, so the message column doesn't jump left.
        self._timestamp_width = 0
        self._module_width = 0
        self.rich_theme = Theme(theme_config["highlights"])
        self.console = Console(
            theme=self.rich_theme,
            highlighter=LogScopeHighlighter(),
            no_color=no_color,
        )

    def _append_message_part(self, text: Text, part: str, base_style: Optional[str]) -> None:
        """Append a message fragment."""
        if self._no_color:
            text.append(part)
            return
        text.append(part, style=base_style)

    def _append_data_dump(
        self, text: Text, data_bytes: List[str], spaced: bool, leading_newline: bool = True
    ) -> None:
        """Append a hex dump of a DATA[..] byte array below the message, using the
        same byte separator (space or none) the original segment used."""
        label = "DATA: "
        indent = "    "
        continuation_indent = " " * (len(indent) + len(label))
        label_style = None if self._no_color else "dim"
        byte_style = label_style
        separator = " " if spaced else ""
        bytes_per_row = _DATA_BYTES_PER_ROW

        if self._wrap_width and self._wrap_width > 0:
            available = max(self._wrap_width - len(continuation_indent), 2)
            # Each byte token takes 2 columns, plus 1 more if separated ("xx ").
            bytes_per_row = max(available // (3 if spaced else 2), 1)

        for row_start in range(0, len(data_bytes), bytes_per_row):
            row = data_bytes[row_start:row_start + bytes_per_row]
            if row_start > 0 or leading_newline:
                text.append("\n")
            if row_start == 0:
                text.append(f"{indent}{label}", style=label_style)
            else:
                text.append(continuation_indent)
            text.append(separator.join(row), style=byte_style)

    def _append_message(
        self,
        text: Text,
        message: str,
        highlight: Optional[str],
        highlight_color: str,
        case_sensitive: bool,
        message_style: Optional[str],
    ) -> None:
        """Append one (possibly wrapped) chunk of the message, applying custom
        keyword highlighting and number highlighting."""
        if highlight and highlight.strip():
            keyword = highlight.strip()
            if self._no_color:
                text.append(message)
            elif case_sensitive:
                # Case-sensitive: simple split
                parts = message.split(keyword)
                if len(parts) > 1:
                    for i, part in enumerate(parts):
                        self._append_message_part(text, part, message_style)
                        if i < len(parts) - 1:
                            text.append(keyword, style=highlight_color)
                else:
                    self._append_message_part(text, message, message_style)
            else:
                # Case-insensitive: use regex to find matches and preserve original case
                pattern = re.compile(re.escape(keyword), re.IGNORECASE)
                last_end = 0
                for match in pattern.finditer(message):
                    self._append_message_part(text, message[last_end:match.start()], message_style)
                    text.append(match.group(), style=highlight_color)
                    last_end = match.end()
                self._append_message_part(text, message[last_end:], message_style)
        else:
            self._append_message_part(text, message, message_style)

    def format_log(self, entry: LogEntry, line_number: Optional[int] = None, highlight: Optional[str] = None, highlight_color: str = "bold magenta", case_sensitive: bool = False) -> Text:
        """Format a log entry with current theme's colors and emojis."""
        text = Text()

        # A line that's nothing but a "DATA[..]" dump belongs to the previous log
        # line (e.g. a UART frame that printed its payload as a follow-up line) -
        # there's no real level to show (it would just be UNKNOWN), so skip the
        # level/timestamp/module header entirely and render only the hex dump.
        is_data_only = (
            entry.level == "UNKNOWN"
            and not entry.message
            and not entry.timestamp_text
            and not entry.service
            and entry.data_bytes
        )
        if is_data_only:
            if line_number is not None:
                text.append(f"{line_number:>4} │ ", style="dim")
            self._append_data_dump(text, entry.data_bytes, entry.data_bytes_spaced, leading_newline=False)
            return text

        icon, style = self.level_mapping.get(entry.level, self.level_mapping.get("UNKNOWN", ("⚪", "dim white")))

        if line_number is not None:
            text.append(f"{line_number:>4} │ ", style="dim")

        if self._has_icons:
            text.append(f"{icon} {entry.level:<7} ", style=style)
        else:
            text.append(f"{entry.level:<7} ", style=style)

        if entry.timestamp_text:
            self._timestamp_width = max(self._timestamp_width, len(entry.timestamp_text))
            text.append(f"{entry.timestamp_text:<{self._timestamp_width}} ", style="logscope.timestamp")
            if entry.service:
                self._module_width = max(self._module_width, len(entry.service))
                text.append(f"{entry.service:<{self._module_width}} ", style="logscope.module")

        # The message renders in the same color as its level's icon/label, so
        # severity stays visible at a glance. --no-color keeps it fully unstyled
        # for clean piping.
        message_style = None if self._no_color else style
        prefix_width = len(text.plain)

        if self._wrap_width and self._wrap_width > 0:
            available = max(self._wrap_width - prefix_width, 10)
            chunks = textwrap.wrap(
                entry.message, width=available, break_long_words=False, break_on_hyphens=False
            ) or [""]
        else:
            chunks = [entry.message]

        for i, chunk in enumerate(chunks):
            if i > 0:
                text.append("\n" + " " * prefix_width)
            self._append_message(text, chunk, highlight, highlight_color, case_sensitive, message_style)

        if entry.data_bytes:
            self._append_data_dump(text, entry.data_bytes, entry.data_bytes_spaced)

        return text

# Global manager instance
manager = LogScopeManager()


def parse_level_filter(level: Optional[str]) -> Optional[Set[str]]:
    if not level or not level.strip():
        return None
    parts = {_normalize_level(p.strip()) for p in level.split(",") if p.strip()}
    return parts or None


def line_passes_level(entry_level: str, allowed: Optional[Set[str]]) -> bool:
    if not allowed:
        return True
    return entry_level in allowed


def line_passes_min_level(entry_level: str, min_level: Optional[str]) -> bool:
    """Check if entry level meets minimum severity threshold."""
    if not min_level:
        return True
    entry_severity = LEVEL_ORDER.get(entry_level, 0)
    min_severity = LEVEL_ORDER.get(_normalize_level(min_level), 0)
    return entry_severity >= min_severity


def line_passes_search(
    line: str,
    search: Optional[str],
    *,
    pattern: Optional[Pattern[str]],
    use_regex: bool,
    case_sensitive: bool,
    invert_match: bool,
) -> bool:
    if not search:
        return True
    if use_regex and pattern is not None:
        matched = pattern.search(line) is not None
    elif case_sensitive:
        matched = search in line
    else:
        matched = search.lower() in line.lower()
    if invert_match:
        return not matched
    return matched


def line_passes_filters(
    entry: LogEntry,
    level_set: Optional[Set[str]],
    search: Optional[str],
    since: Optional[datetime],
    until: Optional[datetime],
    *,
    pattern: Optional[Pattern[str]],
    use_regex: bool,
    case_sensitive: bool,
    invert_match: bool,
    min_level: Optional[str] = None,
) -> bool:
    """Check if an entry passes all filters (level, min_level, search, timestamp)."""
    if not line_passes_level(entry.level, level_set):
        return False
    if not line_passes_min_level(entry.level, min_level):
        return False
    if not line_passes_search(
        entry.raw,
        search,
        pattern=pattern,
        use_regex=use_regex,
        case_sensitive=case_sensitive,
        invert_match=invert_match,
    ):
        return False
    if entry.timestamp:
        if since and entry.timestamp.replace(tzinfo=None) < since.replace(tzinfo=None):
            return False
        if until and entry.timestamp.replace(tzinfo=None) > until.replace(tzinfo=None):
            return False
    return True


def iter_search_context(
    entries: Iterable[Tuple[int, LogEntry]],
    search: Optional[str],
    *,
    pattern: Optional[Pattern[str]],
    use_regex: bool,
    case_sensitive: bool,
    invert_match: bool,
    before_context: int = 0,
    after_context: int = 0,
) -> Iterator[Tuple[int, LogEntry]]:
    """Yield matching entries plus grep-style before/after context lines."""
    if not search or (before_context <= 0 and after_context <= 0):
        for line_number, entry in entries:
            if line_passes_search(
                entry.raw,
                search,
                pattern=pattern,
                use_regex=use_regex,
                case_sensitive=case_sensitive,
                invert_match=invert_match,
            ):
                yield line_number, entry
        return

    before: Deque[Tuple[int, LogEntry]] = deque(maxlen=before_context)
    after_remaining = 0
    emitted: Set[int] = set()

    for line_number, entry in entries:
        matched = line_passes_search(
            entry.raw,
            search,
            pattern=pattern,
            use_regex=use_regex,
            case_sensitive=case_sensitive,
            invert_match=invert_match,
        )

        if matched:
            for buffered_line_number, buffered_entry in before:
                if buffered_line_number not in emitted:
                    emitted.add(buffered_line_number)
                    yield buffered_line_number, buffered_entry

            if line_number not in emitted:
                emitted.add(line_number)
                yield line_number, entry

            after_remaining = max(after_remaining, after_context)
        elif after_remaining > 0:
            if line_number not in emitted:
                emitted.add(line_number)
                yield line_number, entry
            after_remaining -= 1

        before.append((line_number, entry))


def _strip_nul_bytes(line: str) -> str:
    """Drop stray NUL bytes some UART framings (e.g. "\\r\\n\\0" line endings)
    leave attached to the start of the following line; left in place they'd
    otherwise defeat startswith/regex-anchored checks throughout the parser."""
    return line.replace("\x00", "")


def get_lines(file: TextIO, follow: bool):
    """Generator that yields (line_number, line) tuples from a file, optionally tailing it."""
    line_number = 0
    # yield existing lines
    for line in file:
        line_number += 1
        line = _strip_nul_bytes(line)
        if line.strip():
            yield line_number, line

    if not follow:
        return

    # tailing
    manager.console.print("[dim]-- 🔭 Tailing new logs... (Press Ctrl+C to exit) --[/dim]")
    try:
        while True:
            line = file.readline()
            if not line:
                time.sleep(0.1)
                continue
            line_number += 1
            line = _strip_nul_bytes(line)
            if line.strip():
                yield line_number, line
    except KeyboardInterrupt:
        return


def stream_logs(
    file: TextIO,
    follow: bool,
    level: Optional[str] = None,
    search: Optional[str] = None,
    export_html: Optional[Path] = None,
    show_line_numbers: bool = False,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    *,
    use_regex: bool = False,
    search_pattern: Optional[Pattern[str]] = None,
    case_sensitive: bool = False,
    invert_match: bool = False,
    highlight: Optional[str] = None,
    highlight_color: str = "bold magenta",
    min_level: Optional[str] = None,
    before_context: int = 0,
    after_context: int = 0,
):
    """Basic console mode: prints directly to stdout, supporting tails."""
    if export_html:
        manager.console.record = True

    level_set = parse_level_filter(level)

    def filtered_entries() -> Iterator[Tuple[int, LogEntry]]:
        for line_number, line in get_lines(file, follow):
            entry = parse_line(line)
            if line_passes_filters(
                entry,
                level_set,
                None,
                since,
                until,
                pattern=None,
                use_regex=False,
                case_sensitive=False,
                invert_match=False,
                min_level=min_level,
            ):
                yield line_number, entry

    try:
        for line_number, entry in iter_search_context(
            filtered_entries(),
            search,
            pattern=search_pattern,
            use_regex=use_regex,
            case_sensitive=case_sensitive,
            invert_match=invert_match,
            before_context=before_context,
            after_context=after_context,
        ):
            formatted = manager.format_log(
                entry,
                line_number=line_number if show_line_numbers else None,
                highlight=highlight,
                highlight_color=highlight_color,
                case_sensitive=case_sensitive,
            )
            manager.console.print(formatted)
    finally:
        if export_html:
            manager.console.save_html(str(export_html), clear=False)
            manager.console.print(f"\n[bold green]✅ Logs exported successfully to {export_html}[/bold green]")


def run_dashboard(
    file: TextIO,
    follow: bool,
    level_filter: Optional[str] = None,
    search_filter: Optional[str] = None,
    show_line_numbers: bool = False,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    *,
    use_regex: bool = False,
    search_pattern: Optional[Pattern[str]] = None,
    case_sensitive: bool = False,
    invert_match: bool = False,
    highlight: Optional[str] = None,
    highlight_color: str = "bold magenta",
    min_level: Optional[str] = None,
):
    """Dashboard mode: Shows a summary stats panel and recent logs layout."""

    level_set = parse_level_filter(level_filter)

    stats = {
        "FATAL": 0,
        "ALERT": 0,
        "CRITICAL": 0,
        "ERROR": 0,
        "WARN": 0,
        "NOTICE": 0,
        "INFO": 0,
        "DEBUG": 0,
        "TRACE": 0,
        "UNKNOWN": 0
    }
    
    total_processed = 0
    recent_logs: List[Text] = []
    MAX_LOGS = 25 # Number of lines to keep in the scrolling window

    def generate_layout() -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=5),
            Layout(name="body")
        )
        
        # Stats table
        table = Table(show_header=False, expand=True, border_style="dim", box=None)
        table.add_column("C1", justify="center")
        table.add_column("C2", justify="center")
        table.add_column("C3", justify="center")
        table.add_column("C4", justify="center")
        
        table.add_row(
            f"[bold dark_red]💀 Fatal: {stats.get('FATAL', 0)}[/bold dark_red]",
            f"[bold magenta]💥 Critical: {stats.get('CRITICAL', 0)}[/bold magenta]",
            f"[bold red]🔴 Errors: {stats.get('ERROR', 0)}[/bold red]",
            f"[bold yellow]🟡 Warns: {stats.get('WARN', 0)}[/bold yellow]"
        )
        table.add_row(
            f"[bold green]🔵 Info: {stats.get('INFO', 0)}[/bold green]",
            f"[bold blue]🐛 Debug: {stats.get('DEBUG', 0)}[/bold blue]",
            f"[dim white]🔍 Trace: {stats.get('TRACE', 0)}[/dim white]",
            f"[dim white]⚪ Unknown: {stats.get('UNKNOWN', 0)}[/dim white]"
        )
        
        layout["header"].update(Panel(table, title=f"[bold]✨ LogScope Live Dashboard — Total: {total_processed}[/bold]", border_style="cyan"))
        
        # Logs
        log_group = Group(*recent_logs)
        title = "Recent Logs (Auto-highlight enabled)"
        if follow:
            title += " - [blink green]● LIVE[/blink green]"
            
        layout["body"].update(Panel(log_group, title=title))
        
        return layout

    manager.console.clear()
    
    try:
        with Live(generate_layout(), console=manager.console, refresh_per_second=10) as live:
            for line_number, line in get_lines(file, follow):
                total_processed = line_number
                entry = parse_line(line)

                if not line_passes_filters(
                    entry,
                    level_set,
                    search_filter,
                    since,
                    until,
                    pattern=search_pattern,
                    use_regex=use_regex,
                    case_sensitive=case_sensitive,
                    invert_match=invert_match,
                    min_level=min_level,
                ):
                    continue

                # Update stats tally
                entry_level = entry.level if entry.level in stats else "UNKNOWN"
                stats[entry_level] += 1

                formatted = manager.format_log(
                    entry,
                    line_number=total_processed if show_line_numbers else None,
                    highlight=highlight,
                    highlight_color=highlight_color,
                    case_sensitive=case_sensitive,
                )
                recent_logs.append(formatted)
                if len(recent_logs) > MAX_LOGS:
                    recent_logs.pop(0)

                live.update(generate_layout())
    except KeyboardInterrupt:
        pass


_LIVE_HELP_PREFIX = (
    "[dim]/[/dim] search  [dim]r[/dim] regex  [dim]m[/dim] modules  "
    "[dim]c[/dim] clear filters  [dim]p[/dim] clear buffer  [dim]q[/dim] quit\n"
)

_MODULE_PICKER_HELP = (
    "Modules: [dim]↑/↓[/dim] move  [dim]enter[/dim] toggle  "
    "[dim]a[/dim] all/none  [dim]m[/dim] confirm  [dim]esc[/dim] cancel"
)


def _read_char(fd: int) -> str:
    """Read exactly one character straight from the raw file descriptor (not
    through sys.stdin's buffered TextIOWrapper). Keeping every keyboard read in
    this module at the raw-fd level is what lets select() reliably tell whether
    more bytes are already waiting (e.g. to detect arrow-key escape sequences) -
    select() only sees the kernel-level buffer, so mixing it with buffered
    sys.stdin.read() calls causes it to miss bytes Python already siphoned into
    its own userspace buffer."""
    return os.read(fd, 1).decode(errors="replace")


def _resolve_arrow_key(fd: int, first_char: str) -> str:
    """If `first_char` is the start of an arrow-key escape sequence (ESC [ A/B),
    consume and resolve it to 'UP'/'DOWN'; otherwise return it unchanged. A lone
    Escape press (nothing follows within the lookahead window) stays "\\x1b"."""
    if first_char != "\x1b":
        return first_char
    ready, _, _ = select.select([fd], [], [], 0.05)
    if not ready:
        return first_char
    second = _read_char(fd)
    if second != "[":
        return second
    third = _read_char(fd)
    if third == "A":
        return "UP"
    if third == "B":
        return "DOWN"
    return first_char


def _format_live_help_text(state: LiveFilterState) -> str:
    """Build the level-toggle line, graying out levels the user has hidden so
    it's visible at a glance which ones are currently disabled."""
    labels = []
    for key, level in LEVEL_BY_KEY.items():
        label = f"{key}:{level}"
        if level in state.hidden_levels:
            label = f"[dim]{label}[/dim]"
        labels.append(label)
    return f"{_LIVE_HELP_PREFIX}toggle level: " + "  ".join(labels)


def _prompt_line(fd: int, live: Live, generate_layout, status_prefix: str) -> Optional[str]:
    """Blocking single-line text entry (Enter submits, Esc/Ctrl-C cancels,
    Backspace edits), re-rendering the live layout after every keystroke so the
    user sees what they're typing. stdin must already be in cbreak mode."""
    buf: List[str] = []
    while True:
        live.update(generate_layout(f"{status_prefix}{rich_escape(''.join(buf))}[blink]_[/blink]"))
        ch = _read_char(fd)
        if ch in ("\r", "\n"):
            return "".join(buf)
        if ch in ("\x1b", "\x03"):  # Esc or Ctrl-C
            return None
        if ch in ("\x7f", "\x08"):  # Backspace
            if buf:
                buf.pop()
            continue
        if ch.isprintable():
            buf.append(ch)


def _prompt_module_picker(
    fd: int, live: Live, generate_layout, modules: List[str], hidden: Set[str]
) -> Optional[Set[str]]:
    """Interactive multi-select list for toggling module visibility. Up/Down
    move, Enter (or space) toggles the highlighted module, 'a' toggles
    all/none, 'm' confirms (returns the new hidden set), Esc/Ctrl-C cancels
    (returns None, discarding changes made in this session). stdin must
    already be in cbreak mode."""
    picker = ModulePickerState(modules=list(modules), hidden=set(hidden))
    while True:
        live.update(generate_layout(_MODULE_PICKER_HELP, module_picker=picker))
        ch = _resolve_arrow_key(fd, _read_char(fd))
        if ch == "m":
            return picker.hidden
        if ch in ("\x1b", "\x03"):  # Esc or Ctrl-C
            return None
        if ch == "DOWN":
            picker.move(1)
        elif ch == "UP":
            picker.move(-1)
        elif ch in (" ", "\r", "\n"):
            picker.toggle_current()
        elif ch == "a":
            picker.toggle_all()


def run_live_filter(
    file: TextIO,
    follow: bool,
    show_line_numbers: bool = False,
    level_filter: Optional[str] = None,
    module_filter: Optional[str] = None,
    search_filter: Optional[str] = None,
    use_regex: bool = False,
):
    """Interactive terminal mode: buffers up to MAX_LIVE_BUFFER entries and lets
    the user adjust search/regex/module/level filters live with the keyboard,
    re-applying them retroactively over the whole buffer on every change."""
    if not _RAW_TERMINAL_SUPPORTED:
        manager.console.print(
            "[bold red]❌ Error: --live requires a POSIX terminal (termios/tty unavailable here).[/bold red]"
        )
        return

    state = LiveFilterState(
        search=search_filter,
        use_regex=use_regex,
    )
    if module_filter:
        state.hidden_modules = {m.strip() for m in module_filter.split(",") if m.strip()}
    initial_allowed = parse_level_filter(level_filter)
    if initial_allowed:
        state.hidden_levels = {lvl for lvl in LIVE_TOGGLE_LEVELS if lvl not in initial_allowed}

    buffer: Deque[Tuple[int, LogEntry]] = deque(maxlen=MAX_LIVE_BUFFER)
    total_processed = 0
    reading_done = False

    def generate_layout(
        status: Optional[str] = None, module_picker: Optional[ModulePickerState] = None
    ) -> Layout:
        layout = Layout()
        # header holds: title (1) + key-binding line (1) + level-toggle line (1)
        # + optional status/prompt line (1) + panel border (2) = 6. Fixed so a
        # search/regex/module prompt is never clipped off-screen while typing.
        layout.split_column(
            Layout(name="header", size=6),
            Layout(name="body"),
        )

        header_lines = [
            f"[bold]🔎 LogScope Live Filter[/bold] — buffer: {len(buffer)}/{MAX_LIVE_BUFFER} — {rich_escape(state.describe())}",
            _format_live_help_text(state),
        ]
        if status is not None:
            header_lines.append(status)
        layout["header"].update(Panel("\n".join(header_lines), border_style="cyan"))

        if module_picker is not None:
            picker_text = _format_module_picker(module_picker, wrap_width=manager._wrap_width)
            layout["body"].update(Panel(picker_text, title="Select modules to show"))
            return layout

        visible = filter_live_buffer(buffer, state)
        tail = visible[-MAX_LIVE_VISIBLE_LOGS:]
        log_group = Group(*(
            manager.format_log(entry, line_number=line_number if show_line_numbers else None)
            for line_number, entry in tail
        ))
        title = f"Logs ({len(visible)}/{len(buffer)} shown)"
        if follow and not reading_done:
            title += " - [blink green]● LIVE[/blink green]"
        layout["body"].update(Panel(log_group, title=title))
        return layout

    manager.console.clear()
    stdin_fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(stdin_fd)
    try:
        file_fd = file.fileno()
    except (AttributeError, OSError, ValueError):
        file_fd = None

    try:
        tty.setcbreak(stdin_fd)
        with Live(generate_layout(), console=manager.console, refresh_per_second=10) as live:
            while True:
                watch = [stdin_fd]
                if file_fd is not None and not reading_done:
                    watch.append(file_fd)
                ready, _, _ = select.select(watch, [], [], 0.1)

                dirty = False

                if file_fd is not None and file_fd in ready:
                    line = file.readline()
                    if line:
                        total_processed += 1
                        line = _strip_nul_bytes(line)
                        if line.strip():
                            buffer.append((total_processed, parse_line(line)))
                            dirty = True
                    elif not follow:
                        reading_done = True
                        dirty = True

                if stdin_fd in ready:
                    key = _read_char(stdin_fd)
                    if key == "q":
                        break
                    elif key == "c":
                        state.search = None
                        state.hidden_modules = set()
                        state.hidden_levels = set()
                        dirty = True
                    elif key == "p":
                        buffer.clear()
                        dirty = True
                    elif key == "r":
                        typed = _prompt_line(stdin_fd, live, generate_layout, "Regex: ")
                        if typed is not None:
                            state.search = typed or None
                            state.use_regex = True
                        dirty = True
                    elif key == "/":
                        typed = _prompt_line(stdin_fd, live, generate_layout, "Search: ")
                        if typed is not None:
                            state.search = typed or None
                            state.use_regex = False
                        dirty = True
                    elif key == "m":
                        known_modules = sorted({entry.service for _, entry in buffer if entry.service})
                        result = _prompt_module_picker(stdin_fd, live, generate_layout, known_modules, state.hidden_modules)
                        if result is not None:
                            state.hidden_modules = result
                        dirty = True
                    elif key in LEVEL_BY_KEY:
                        level = LEVEL_BY_KEY[key]
                        if level in state.hidden_levels:
                            state.hidden_levels.discard(level)
                        else:
                            state.hidden_levels.add(level)
                        dirty = True

                if dirty:
                    live.update(generate_layout())
    except KeyboardInterrupt:
        pass
    finally:
        termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_settings)
