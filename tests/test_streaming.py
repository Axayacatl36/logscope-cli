"""Tests that logscope can follow a live, trickling input stream (e.g. a UART line)."""

import os
import threading
import time

import pytest

from logscope.parser import parse_line
from logscope.viewer import get_lines

pytestmark = pytest.mark.skipif(
    not hasattr(os, "mkfifo"), reason="FIFOs require a POSIX OS"
)


def _feed_uart_like_stream(fifo_path: str) -> None:
    """Write to the FIFO the way a UART bridge would: in small delayed chunks,
    with one line split mid-frame, and with a real gap (writer closing and
    reopening) so the reader has to keep polling rather than getting it all
    in one read.
    """
    with open(fifo_path, "w", encoding="utf-8") as fifo:
        fifo.write("[00:00:06.900,512] <inf> Less4_Exer2: The factorial of  1 = 1\n")
        fifo.flush()
        time.sleep(0.1)

        # Line arrives split across two writes, as a UART frame often does.
        fifo.write("[00:00:06.900,543] <in")
        fifo.flush()
        time.sleep(0.1)
        fifo.write("f> Less4_Exer2: The factorial of  2 = 2\n")
        fifo.flush()
        time.sleep(0.1)

        # Malformed frame: missing the timestamp's opening bracket.
        fifo.write("00:00:06.900,573] <dbg> Less4_Exer2: missing opening bracket\n")
        fifo.flush()

    # Writer disconnects entirely, forcing a real (if temporary) EOF on the
    # reader before more data shows up - this is what actually exercises the
    # --follow retry loop in get_lines(), not just a single buffered read.
    time.sleep(0.3)

    with open(fifo_path, "w", encoding="utf-8") as fifo:
        fifo.write("[00:00:06.900,600] <err> Less4_Exer2: reconnected after gap\n")
        fifo.flush()


def test_get_lines_follows_a_live_uart_like_stream(tmp_path):
    """`get_lines(..., follow=True)` should pick up lines as they trickle in
    over a FIFO, including one split mid-write and one after a writer-side
    disconnect/reconnect gap."""
    fifo_path = tmp_path / "uart.fifo"
    os.mkfifo(fifo_path)

    writer = threading.Thread(target=_feed_uart_like_stream, args=(str(fifo_path),), daemon=True)
    writer.start()

    entries = []
    with open(fifo_path, "r", encoding="utf-8") as fifo_file:
        gen = get_lines(fifo_file, follow=True)
        try:
            deadline = time.time() + 10
            while len(entries) < 4 and time.time() < deadline:
                _, line = next(gen)
                entries.append(parse_line(line))
        finally:
            gen.close()

    writer.join(timeout=5)
    assert not writer.is_alive()
    assert len(entries) == 4

    assert entries[0].level == "INFO"
    assert entries[0].service == "Less4_Exer2"
    assert entries[0].message == "The factorial of  1 = 1"

    # The line split across two writes must still be reassembled correctly.
    assert entries[1].level == "INFO"
    assert entries[1].service == "Less4_Exer2"
    assert entries[1].message == "The factorial of  2 = 2"

    # Missing opening timestamp bracket must still be tolerated.
    assert entries[2].level == "DEBUG"
    assert entries[2].service == "Less4_Exer2"
    assert entries[2].message == "missing opening bracket"

    # Line arriving after the writer disconnected and reconnected.
    assert entries[3].level == "ERROR"
    assert entries[3].service == "Less4_Exer2"
    assert entries[3].message == "reconnected after gap"
