"""Live capture through a dumpcap child process. See design §9.1.

dumpcap is the only component with capture privileges (file capabilities or the wireshark
group); netgrapher reads its pcapng stream from a pipe and never needs root. dumpcap runs in
its own session so a Ctrl-C in the terminal reaches only netgrapher, which then stops dumpcap
cleanly.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import threading
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import BinaryIO

from netgrapher.capture.source import (
    CaptureFormatError,
    CaptureReader,
    CaptureStats,
    InterfaceInfo,
    RawPacket,
    Readable,
)

DUMPCAP_ENV = "NETGRAPHER_DUMPCAP"
_MAX_STDERR_LINES = 50


class LiveCaptureError(Exception):
    """dumpcap could not be started or failed."""


def find_dumpcap() -> str | None:
    return os.environ.get(DUMPCAP_ENV) or shutil.which("dumpcap")


class _Tee:
    """Copies everything read from a stream into a file (the -w option)."""

    def __init__(self, source: Readable, sink: BinaryIO) -> None:
        self._source = source
        self._sink = sink

    def read(self, n: int = -1, /) -> bytes:
        data = self._source.read(n)
        if data:
            self._sink.write(data)
        return data


class LiveSource:
    def __init__(
        self,
        interfaces: Sequence[str],
        *,
        snaplen: int = 512,
        buffer_mib: int = 64,
        promiscuous: bool = True,
        bpf_filter: str | None = None,
        write_path: Path | None = None,
        dumpcap: str | None = None,
    ) -> None:
        if not interfaces:
            raise ValueError("at least one interface is required")
        self.interface_names = list(interfaces)
        self.snaplen = snaplen
        self.buffer_mib = buffer_mib
        self.promiscuous = promiscuous
        self.bpf_filter = bpf_filter
        self.write_path = write_path
        self.dumpcap = dumpcap or find_dumpcap()
        self._proc: subprocess.Popen[bytes] | None = None
        self._reader: CaptureReader | None = None
        self._stderr: list[str] = []
        self._stderr_thread: threading.Thread | None = None
        self._stopping = False

    def command(self) -> list[str]:
        if self.dumpcap is None:
            raise LiveCaptureError("dumpcap not found; install wireshark-common (see `doctor`)")
        cmd = [self.dumpcap, "-q"]
        for name in self.interface_names:
            cmd += ["-i", name]
        cmd += ["-s", str(self.snaplen), "-B", str(self.buffer_mib)]
        if not self.promiscuous:
            cmd.append("-p")
        if self.bpf_filter:
            cmd += ["-f", self.bpf_filter]
        cmd += ["-w", "-"]
        return cmd

    def __iter__(self) -> Iterator[RawPacket]:
        try:
            self._proc = subprocess.Popen(
                self.command(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except OSError as exc:
            raise LiveCaptureError(f"cannot start dumpcap: {exc}") from exc
        assert self._proc.stdout is not None and self._proc.stderr is not None
        self._stderr_thread = threading.Thread(
            target=self._drain_stderr, args=(self._proc.stderr,), daemon=True
        )
        self._stderr_thread.start()

        sink = self.write_path.open("wb") if self.write_path else None
        stream: Readable = _Tee(self._proc.stdout, sink) if sink else self._proc.stdout
        self._reader = CaptureReader(stream)
        try:
            yield from self._reader
        except CaptureFormatError as exc:
            if not self._stopping:
                self._wait()
                raise LiveCaptureError(self._failure(f"unexpected output ({exc})")) from exc
        finally:
            if sink:
                sink.close()
            rc = self._wait()
        if rc != 0 and not self._stopping:
            raise LiveCaptureError(self._failure(f"exited with status {rc}"))

    def stop(self) -> None:
        """Ask dumpcap to finish; the stream then ends after the remaining packets."""
        self._stopping = True
        if self._proc is not None and self._proc.poll() is None:
            self._proc.send_signal(signal.SIGINT)

    def kill(self) -> None:
        self._stopping = True
        if self._proc is not None and self._proc.poll() is None:
            self._proc.kill()

    @property
    def stats(self) -> CaptureStats:
        return self._reader.stats if self._reader else CaptureStats()

    @property
    def interfaces(self) -> list[InterfaceInfo]:
        return self._reader.interfaces if self._reader else []

    def _wait(self) -> int:
        assert self._proc is not None
        try:
            return self._proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            return self._proc.wait()

    def _drain_stderr(self, stream: BinaryIO) -> None:
        for line in stream:
            if len(self._stderr) < _MAX_STDERR_LINES:
                self._stderr.append(line.decode("utf-8", "replace").rstrip())

    def _failure(self, what: str) -> str:
        if self._stderr_thread is not None:
            self._stderr_thread.join(timeout=2)
        details = "\n".join(line for line in self._stderr if line.strip())
        return f"dumpcap {what}" + (f":\n{details}" if details else "")
