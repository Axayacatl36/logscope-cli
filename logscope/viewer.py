import re
import sys
import textwrap
import time
from collections import deque
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
from rich.theme import Theme

from .parser import parse_line, LogEntry, _normalize_level
from .themes import DEFAULT_THEMES

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


def get_lines(file: TextIO, follow: bool):
    """Generator that yields (line_number, line) tuples from a file, optionally tailing it."""
    line_number = 0
    # yield existing lines
    for line in file:
        line_number += 1
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
