import re
import json
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Tuple

# Compiled regex patterns for performance
_BRACKET_LEVEL_PATTERN = re.compile(
    r'\[(TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|ERR|CRITICAL|ALERT|FATAL|EMERGENCY)\]',
    re.IGNORECASE
)
_BRACKETLESS_LEVEL_PATTERN = re.compile(
    r'\b(TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|ERR|CRITICAL|ALERT|FATAL|EMERGENCY)\b',
    re.IGNORECASE
)

# Multiple timestamp patterns for different log formats
_TIMESTAMP_PATTERNS = [
    # ISO 8601: 2026-03-21T10:00:00Z or 2026-03-21T10:00:00.123Z or 2026-03-21T10:00:00+00:00
    re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)'),
    # ISO-like with space: 2026-03-21 10:00:00 or 2026-03-21 10:00:00.123
    re.compile(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)'),
    # Common Log Format / Apache: 21/Mar/2026:10:00:00 +0000 or [21/Mar/2026:10:00:00 +0000]
    re.compile(r'(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{4})?)'),
    # Syslog-style: Mar 21 10:00:00 (year is assumed current year)
    re.compile(r'([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'),
    # Unix timestamp: 1711054800 (10 digits for seconds)
    re.compile(r'\b(\d{10})\b'),
]

# Month name mapping for parsing
_MONTH_MAP = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
}

# Zephyr RTOS log lines look like "[00:00:06.900,512] <inf> module: message".
# They're commonly streamed over UART, where dropped/garbled bytes routinely eat
# the brackets around the timestamp or the angle brackets around the level tag,
# or glue stray characters onto the front of the line. Each piece is therefore
# matched independently (with its delimiters optional) rather than as one rigid
# line-level pattern, so a corrupted delimiter doesn't stop the rest of the line
# from being recognized.
_ZEPHYR_TIMESTAMP_PATTERN = re.compile(r'\[?(\d{2}:\d{2}:\d{2}\.\d{3},\d{3})\]?')
# Fallback for uptime formats that don't match the digit layout above (e.g. a plain
# tick counter or a timestamp without the ",uuu" suffix): treat whatever sits
# between a bracket pair as the timestamp. This is only trusted once a level tag
# is also found afterward (see _parse_zephyr_line), so it can't hijack plain
# "[LEVEL] message" lines that have no separate timestamp field.
_GENERIC_BRACKET_PATTERN = re.compile(r'\[([^\[\]]+)\]')
_ZEPHYR_LEVEL_PATTERN = re.compile(r'<?\b(err|wrn|inf|dbg)\b>?', re.IGNORECASE)
_ZEPHYR_MODULE_PATTERN = re.compile(r'([\w./-]+):\s*(.*)$')
_ZEPHYR_LEVEL_ABBR_MAP = {
    "err": "ERROR",
    "wrn": "WARN",
    "inf": "INFO",
    "dbg": "DEBUG",
}

# A "DATA[..]" segment embedded in a message is a raw uint8_t byte dump, e.g.
# "DATA[12 34 56 78 90 a1 b2 c3 d4 e5 f6 ff ff ff ee ab ab ab]". It's pulled out
# of the message so the viewer can render it separately as a readable hex dump.
_DATA_SEGMENT_PATTERN = re.compile(r'DATA\[([^\]]*)\]', re.IGNORECASE)

@dataclass
class LogEntry:
    level: str
    message: str
    raw: str
    timestamp: Optional[datetime] = None
    service: Optional[str] = None
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    # Display-ready timestamp text for formats (e.g. Zephyr uptime) whose timestamp
    # isn't a real calendar date/time and therefore can't populate `timestamp` above.
    timestamp_text: Optional[str] = None
    # Byte values (normalized to lowercase two-digit hex, e.g. "0a") pulled out of
    # a "DATA[..]" segment in the message, for the viewer to render as a hex dump.
    data_bytes: Optional[List[str]] = None


# Level normalization constants
_NORMALIZE_LEVEL_MAP = {
    "WARNING": "WARN",
    "EMERGENCY": "FATAL",
    "ERR": "ERROR",
}
_JSON_LEVEL_KEYS = ("level", "severity", "log.level", "severity_text", "severityText")
_JSON_MESSAGE_KEYS = ("message", "msg", "text", "body", "log")
_JSON_TIMESTAMP_KEYS = ("timestamp", "time", "@timestamp")
_MISSING = object()


def _normalize_level(level: str) -> str:
    """Normalize log level aliases to canonical forms."""
    return _NORMALIZE_LEVEL_MAP.get(level.upper(), level.upper())


def _first_json_value(data: dict, keys: Tuple[str, ...]):
    """Return the first present JSON value from a list of common log field names."""
    for key in keys:
        if key in data:
            return data[key]
    return _MISSING


def _stringify_json_message(value, raw_line: str) -> str:
    """Convert JSON message-like values to stable display text."""
    if value is _MISSING:
        return raw_line
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value).rstrip("\r\n")


def _extract_json_observability(data: dict) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Pull service / trace / span from common JSON log shapes (K8s, OTel, Docker)."""
    k8s = data.get("kubernetes")
    k8s_d: dict = k8s if isinstance(k8s, dict) else {}
    pod_name = k8s_d.get("pod_name")
    if not pod_name and isinstance(k8s_d.get("pod"), dict):
        pod_name = k8s_d["pod"].get("name")

    resource = data.get("resource")
    resource_d: dict = resource if isinstance(resource, dict) else {}
    resource_attrs = resource_d.get("attributes")
    resource_attrs_d: dict = resource_attrs if isinstance(resource_attrs, dict) else {}

    service = (
        data.get("service")
        or data.get("service.name")
        or data.get("service_name")
        or data.get("resource.attributes.service.name")
        or resource_attrs_d.get("service.name")
        or resource_attrs_d.get("service_name")
        or pod_name
        or k8s_d.get("container_name")
        or data.get("container")
        or data.get("container.name")
        or data.get("logger")
        or data.get("logger.name")
    )
    if service is not None:
        service = str(service)

    trace_id = data.get("trace_id") or data.get("traceId") or data.get("trace.id")
    if not trace_id and isinstance(data.get("trace"), dict):
        trace_id = data["trace"].get("id")
    if not trace_id and isinstance(data.get("otelTraceID"), str):
        trace_id = data["otelTraceID"]
    if trace_id is not None:
        trace_id = str(trace_id)

    span_id = data.get("span_id") or data.get("spanId") or data.get("span.id")
    if span_id is not None:
        span_id = str(span_id)

    return service, trace_id, span_id

def _parse_zephyr_line(line: str) -> Optional[LogEntry]:
    """Parse a Zephyr-style log line, tolerating missing/garbled delimiters.

    The distinctive "HH:MM:SS.mmm,uuu" uptime timestamp is enough on its own to
    recognize the line as Zephyr; the surrounding brackets, the level's angle
    brackets, and any junk prefix (e.g. from a torn UART frame) are all optional.
    If that specific digit layout isn't found (some builds log plain tick counters
    or a coarser timestamp), any bracketed segment is accepted as the timestamp
    instead - but only once a level tag is also found afterward, so this fallback
    can't hijack plain "[LEVEL] message" lines that have no separate timestamp.
    """
    ts_match = _ZEPHYR_TIMESTAMP_PATTERN.search(line)
    if ts_match:
        timestamp_text = f"[{ts_match.group(1)}]"
        remainder = line[ts_match.end():]
        require_level = False
    else:
        bracket_match = _GENERIC_BRACKET_PATTERN.search(line)
        if not bracket_match:
            return None
        timestamp_text = f"[{bracket_match.group(1)}]"
        remainder = line[bracket_match.end():]
        require_level = True

    level = None
    level_match = _ZEPHYR_LEVEL_PATTERN.search(remainder)
    if level_match:
        level = _ZEPHYR_LEVEL_ABBR_MAP[level_match.group(1).lower()]
        remainder = remainder[level_match.end():]
    else:
        # Fall back to a spelled-out level (e.g. "INFO" with no angle brackets at all)
        full_match = _BRACKET_LEVEL_PATTERN.search(remainder) or _BRACKETLESS_LEVEL_PATTERN.search(remainder)
        if full_match:
            level = _normalize_level(full_match.group(1))
            remainder = remainder[full_match.end():]

    if level is None and require_level:
        return None

    remainder = remainder.strip()

    service = None
    module_match = _ZEPHYR_MODULE_PATTERN.match(remainder)
    if module_match:
        service = module_match.group(1)
        message = module_match.group(2).strip()
    else:
        message = remainder

    return LogEntry(
        level=level or "UNKNOWN",
        message=message,
        raw=line,
        service=service,
        timestamp_text=timestamp_text,
    )


def _extract_data_segment(message: str) -> Tuple[str, Optional[List[str]]]:
    """Pull a "DATA[..]" hex byte dump out of a message, if present.

    Returns the message with the segment removed, and the byte values
    normalized to lowercase two-digit hex (e.g. "0a"), or (message, None) if
    no valid segment was found.
    """
    match = _DATA_SEGMENT_PATTERN.search(message)
    if not match:
        return message, None

    data_bytes = []
    for token in match.group(1).split():
        try:
            data_bytes.append(f"{int(token, 16):02x}")
        except ValueError:
            return message, None

    if not data_bytes:
        return message, None

    cleaned_message = (message[:match.start()] + message[match.end():]).strip()
    return cleaned_message, data_bytes


def parse_line(line: str) -> LogEntry:
    """Parse a single line of log, extracting severity level and any DATA[..] byte dump."""
    entry = _parse_line_impl(line)
    message, data_bytes = _extract_data_segment(entry.message)
    if data_bytes is not None:
        entry.message = message
        entry.data_bytes = data_bytes
    return entry


def _parse_line_impl(line: str) -> LogEntry:
    """Parse a single line of log and extract severity level."""
    line = line.strip()

    # 1. Check if JSON log object (common in docker/kubernetes/modern APIs)
    if line.startswith('{') and line.endswith('}'):
        try:
            data = json.loads(line)
            level_value = _first_json_value(data, _JSON_LEVEL_KEYS)
            message = _stringify_json_message(_first_json_value(data, _JSON_MESSAGE_KEYS), line)
            if level_value is _MISSING:
                inner_entry = parse_line(message) if message != line else None
                level = inner_entry.level if inner_entry and inner_entry.level != "UNKNOWN" else "UNKNOWN"
                if inner_entry and inner_entry.level != "UNKNOWN":
                    message = inner_entry.message
            else:
                level = _normalize_level(str(level_value))
            
            # Find timestamp
            timestamp_str = _first_json_value(data, _JSON_TIMESTAMP_KEYS)
            timestamp = None
            if timestamp_str is not _MISSING and timestamp_str:
                try:
                    # Basic ISO parsing
                    timestamp = datetime.fromisoformat(str(timestamp_str).replace('Z', '+00:00'))
                except ValueError:
                    pass

            svc, tid, sid = _extract_json_observability(data)
            return LogEntry(
                level=level,
                message=message,
                raw=line,
                timestamp=timestamp,
                service=svc,
                trace_id=tid,
                span_id=sid,
            )
        except json.JSONDecodeError:
            pass

    # 2. Zephyr RTOS logs (e.g. "[00:00:06.900,512] <inf> module: message")
    zephyr_entry = _parse_zephyr_line(line)
    if zephyr_entry is not None:
        return zephyr_entry

    # 3. Try typical log formats like [INFO], (WARN), ERROR:
    match = _BRACKET_LEVEL_PATTERN.search(line)
    if not match:
        # Try finding without brackets as a fallback, e.g. "INFO:" or "INFO - "
        match = _BRACKETLESS_LEVEL_PATTERN.search(line)

    if match:
        level = _normalize_level(match.group(1))

        # Remove the [LEVEL] part from the message for cleaner display
        message = line.replace(match.group(0), '', 1).strip()
        
        # Clean up common separators left behind like ": " or "- "
        if message.startswith(':') or message.startswith('-'):
            message = message[1:].strip()
            
        return LogEntry(level=level, message=message, raw=line, timestamp=extract_timestamp(line))
    
    # fallback
    return LogEntry(level="UNKNOWN", message=line, raw=line, timestamp=extract_timestamp(line))

def extract_timestamp(text: str) -> Optional[datetime]:
    """Extract a timestamp from a raw string using multiple format patterns."""
    for pattern in _TIMESTAMP_PATTERNS:
        match = pattern.search(text)
        if match:
            ts_str = match.group(1)
            try:
                # Try ISO format first (handles most cases)
                if '-' in ts_str and ('T' in ts_str or ts_str[10:11] == ' '):
                    # Handle ISO-like with space instead of T
                    return datetime.fromisoformat(ts_str.replace('Z', '+00:00').replace(' ', 'T'))
                # Handle Common Log Format: 21/Mar/2026:10:00:00 +0000
                elif '/' in ts_str:
                    parts = ts_str.split()
                    main_part = parts[0]
                    # Parse: DD/Mon/YYYY:HH:MM:SS
                    match_parts = re.match(r'(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})', main_part)
                    if match_parts:
                        day, month_str, year, hour, minute, second = match_parts.groups()
                        month = _MONTH_MAP.get(month_str, 1)
                        return datetime(int(year), month, int(day), int(hour), int(minute), int(second))
                # Handle Syslog-style: Mar 21 10:00:00
                elif ts_str[0].isalpha():
                    match_parts = re.match(r'([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})', ts_str)
                    if match_parts:
                        month_str, day, hour, minute, second = match_parts.groups()
                        month = _MONTH_MAP.get(month_str, 1)
                        year = datetime.now().year  # Assume current year
                        return datetime(year, month, int(day), int(hour), int(minute), int(second))
                # Handle Unix timestamp
                elif ts_str.isdigit():
                    return datetime.fromtimestamp(int(ts_str))
            except (ValueError, OSError):
                continue
    return None
