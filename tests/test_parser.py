from logscope.parser import parse_line

def test_parse_info_brackets():
    entry = parse_line("[INFO] System up and running.")
    assert entry.level == "INFO"
    assert entry.message == "System up and running."

def test_parse_error_no_brackets():
    entry = parse_line("ERROR: Disk space is low.")
    assert entry.level == "ERROR"
    assert entry.message == "Disk space is low."

def test_parse_warning_normalize():
    entry = parse_line("[WARNING] Deprecated feature used.")
    assert entry.level == "WARN"
    assert entry.message == "Deprecated feature used."

def test_parse_trace():
    entry = parse_line("[TRACE] - entering method fn()")
    assert entry.level == "TRACE"
    assert entry.message == "entering method fn()"

def test_parse_json_log():
    log_line = '{"timestamp": "2026-03-14T15:30:00", "level": "fatal", "message": "Kernel panic"}'
    entry = parse_line(log_line)
    assert entry.level == "FATAL"
    assert entry.message == "Kernel panic"

def test_parse_json_log_alternative_keys():
    log_line = '{"log.level": "debug", "msg": "Entering function A"}'
    entry = parse_line(log_line)
    assert entry.level == "DEBUG"
    assert entry.message == "Entering function A"

def test_parse_unknown():
    entry = parse_line("Just some random text without a level")
    assert entry.level == "UNKNOWN"
    assert entry.message == "Just some random text without a level"


def test_parse_json_observability_fields():
    log_line = (
        '{"level":"error","message":"timeout","service":"checkout-api",'
        '"trace_id":"abcd1234efgh5678ijklmnop","span_id":"span99"}'
    )
    entry = parse_line(log_line)
    assert entry.level == "ERROR"
    assert entry.service == "checkout-api"
    assert entry.trace_id == "abcd1234efgh5678ijklmnop"
    assert entry.span_id == "span99"


def test_parse_docker_json_log_message_and_inner_level():
    log_line = '{"log":"[ERROR] payment failed\\n","stream":"stderr","time":"2026-03-14T15:30:00Z"}'
    entry = parse_line(log_line)
    assert entry.level == "ERROR"
    assert entry.message == "payment failed"
    assert entry.timestamp is not None


def test_parse_zephyr_full_format():
    entry = parse_line("[00:00:06.900,512] <inf> Less4_Exer2: The factorial of  1 = 1 ")
    assert entry.level == "INFO"
    assert entry.service == "Less4_Exer2"
    assert entry.message == "The factorial of  1 = 1"
    assert entry.timestamp_text == "[00:00:06.900,512]"


def test_parse_zephyr_spelled_out_level_no_brackets():
    entry = parse_line("00:00:06.900,482 INFO Less4_Exer2: Calculating the factorials of numbers 1 to 10: ")
    assert entry.level == "INFO"
    assert entry.service == "Less4_Exer2"


def test_parse_zephyr_garbage_prefix():
    entry = parse_line("something[00:00:06.900,512] <err> Less4_Exer2: The factorial of  2 = 2 ")
    assert entry.level == "ERROR"
    assert entry.service == "Less4_Exer2"
    assert entry.message == "The factorial of  2 = 2"


def test_parse_zephyr_missing_opening_timestamp_bracket():
    entry = parse_line("00:00:06.900,512] <dbg> Less4_Exer2: The factorial of  3 = 6 ")
    assert entry.level == "DEBUG"
    assert entry.service == "Less4_Exer2"
    assert entry.message == "The factorial of  3 = 6"
    assert entry.timestamp_text == "[00:00:06.900,512]"


def test_parse_zephyr_missing_level_opening_bracket():
    entry = parse_line("[00:00:06.900,543] wrn> Less4_Exer2: The factorial of  4 = 24 ")
    assert entry.level == "WARN"
    assert entry.service == "Less4_Exer2"
    assert entry.message == "The factorial of  4 = 24"


def test_parse_zephyr_generic_bracket_timestamp_without_microseconds():
    """A timestamp that doesn't match the strict digit layout is still accepted
    as long as a level tag follows, using the bracket content verbatim."""
    entry = parse_line("[00:00:07] <inf> mod: msg without microseconds")
    assert entry.level == "INFO"
    assert entry.service == "mod"
    assert entry.message == "msg without microseconds"
    assert entry.timestamp_text == "[00:00:07]"


def test_parse_zephyr_generic_bracket_timestamp_tick_counter():
    entry = parse_line("[123456] <err> ticks: raw tick counter timestamp")
    assert entry.level == "ERROR"
    assert entry.service == "ticks"
    assert entry.timestamp_text == "[123456]"


def test_parse_bracket_level_not_hijacked_by_generic_timestamp_fallback():
    """A plain "[LEVEL] message" line has no separate timestamp field, so the
    generic bracket fallback must not swallow the level bracket itself."""
    entry = parse_line("[INFO] System up and running.")
    assert entry.level == "INFO"
    assert entry.message == "System up and running."
    assert entry.timestamp_text is None


def test_parse_zephyr_data_segment_extracted_from_message():
    entry = parse_line(
        "[00:00:06.900,573] <inf> Less4_Exer2: The factorial of 10 = 0x12f "
        "DATA[12 34 56 78 90 a1 b2 c3 d4 e5 f6 ff ff ff ee ab ab ab]"
    )
    assert entry.level == "INFO"
    assert entry.service == "Less4_Exer2"
    assert entry.message == "The factorial of 10 = 0x12f"
    assert entry.data_bytes == [
        "12", "34", "56", "78", "90", "a1", "b2", "c3",
        "d4", "e5", "f6", "ff", "ff", "ff", "ee", "ab", "ab", "ab",
    ]


def test_parse_data_segment_normalizes_single_digit_hex_bytes():
    entry = parse_line("[INFO] payload DATA[1 a f0]")
    assert entry.message == "payload"
    assert entry.data_bytes == ["01", "0a", "f0"]


def test_parse_data_segment_without_separators():
    """Bytes run together with no whitespace should still split into 2-digit bytes."""
    entry = parse_line(
        "[00:00:06.900,573] <inf> Less4_Exer2: msg "
        "DATA[1234567890a1b2c3d4e5f6ffffffeeababab]"
    )
    assert entry.message == "msg"
    assert entry.data_bytes == [
        "12", "34", "56", "78", "90", "a1", "b2", "c3",
        "d4", "e5", "f6", "ff", "ff", "ff", "ee", "ab", "ab", "ab",
    ]


def test_parse_data_segment_without_separators_odd_length():
    """A trailing lone hex digit becomes its own zero-padded byte."""
    entry = parse_line("[INFO] payload DATA[abc]")
    assert entry.message == "payload"
    assert entry.data_bytes == ["ab", "0c"]


def test_parse_no_data_segment_leaves_entry_unchanged():
    entry = parse_line("[INFO] System up and running.")
    assert entry.message == "System up and running."
    assert entry.data_bytes is None


def test_parse_opentelemetry_json_fields():
    log_line = (
        '{"severity_text":"warn","body":"checkout latency high",'
        '"resource":{"attributes":{"service.name":"checkout-api"}},'
        '"trace_id":"4bf92f3577b34da6a3ce929d0e0e4736",'
        '"span_id":"00f067aa0ba902b7"}'
    )
    entry = parse_line(log_line)
    assert entry.level == "WARN"
    assert entry.message == "checkout latency high"
    assert entry.service == "checkout-api"
    assert entry.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert entry.span_id == "00f067aa0ba902b7"
