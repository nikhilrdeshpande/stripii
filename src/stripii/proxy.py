"""A local proxy that redacts on the way out and restores on the way back.

A command-line tool only helps people willing to run a command line. The market
for this has largely moved to a gateway: something that sits between the app and
the model API, so redaction happens whether or not anyone remembers to ask for
it. Point any client at ``http://127.0.0.1:8080`` and it keeps working, except
that personal data no longer leaves the machine.

    stripii proxy --upstream https://api.anthropic.com --profile health

The reversal is what makes this usable rather than merely safe. The model sees
``[[PERSON_1]]``, reasons about it perfectly well, and the reply is rehydrated
before the client ever sees it -- so the answer names the actual person.

Built on the standard library so the proxy adds no dependencies. Binds to
loopback by default: a redaction proxy reachable from the network would be an
unauthenticated relay to a paid API holding somebody's key.

What it refuses, because each would otherwise reach the upstream unredacted:

* a body that is not JSON, or that is compressed (``Content-Encoding``) -- it
  cannot be read, so it cannot be scrubbed;
* base64 images, PDFs, audio and files, unless started with
  ``allow_binary=True`` (``--allow-binary-uploads``): nothing inside them can
  be redacted, so sending them is a decision for the user, not a default;
* a ``Host`` header that is not this machine, which is what a web page doing
  DNS rebinding would send;
* a request target that is not a plain path, and an upstream that is plain
  ``http`` anywhere but loopback.

Every other string in the request is scrubbed -- not only the message text,
but tool inputs, tool-call arguments (parsed from their JSON string), document
blocks, metadata -- except a short list of structural fields (model, role,
type, ids, tool names) that the API needs exactly as sent.
"""

from __future__ import annotations

import json
import re
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .engine import Scrubber
from .vault import Vault

#: Headers that belong to our hop and must not be forwarded verbatim.
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
    "accept-encoding",
}

#: String fields that are structure, not content, and must reach the API
#: exactly as sent. Every other string in a request is scrubbed. ``name`` is
#: here only for tools (see ``_names_a_tool``): a chat message's ``name`` can be
#: a person's.
STRUCTURAL_KEYS = frozenset({
    "model", "role", "type", "id", "tool_use_id", "tool_call_id", "call_id",
    "media_type", "file_id", "signature", "encrypted_content", "cache_control",
    "stop_reason", "finish_reason", "service_tier", "format", "pattern", "required",
    "tool_choice", "reasoning_effort", "modality", "detail", "previous_response_id",
})

#: Content-block types that name a tool call or definition, whose ``name``
#: must not change.
TOOL_TYPES = frozenset({
    "tool_use", "server_tool_use", "mcp_tool_use", "function", "function_call",
    "custom", "custom_tool_call", "tool",
})

#: Largest request body accepted. Base64 PDFs aside, a prompt is far smaller.
MAX_BODY = 32 * 1024 * 1024

#: Host header values that mean "this machine". Anything else on a loopback
#: listener is a browser that was pointed here by DNS rebinding.
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class RefusedRequest(ValueError):
    """A request the proxy will not forward, with the status to answer it with."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


class BinaryContent(RefusedRequest):
    def __init__(self, where: str) -> None:
        super().__init__(
            400,
            f"refusing to forward base64 content ({where}): images, PDFs, audio and "
            "files cannot be redacted. Paste the text instead, redact the file with "
            "`stripii scrub`, or start the proxy with --allow-binary-uploads to send "
            "such content unredacted.",
        )

#: Response fields carrying generated text, for rehydration.
TEXT_KEYS = ("text", "content", "reasoning", "thinking")

DEFAULT_UPSTREAM = "https://api.anthropic.com"


@dataclass
class ProxyStats:
    requests: int = 0
    redactions: int = 0
    per_entity: dict[str, int] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def record(self, counts: dict[str, int]) -> None:
        with self.lock:
            self.requests += 1
            for entity, count in counts.items():
                self.redactions += count
                self.per_entity[entity] = self.per_entity.get(entity, 0) + count


# --------------------------------------------------------------------------
# walking request and response bodies
# --------------------------------------------------------------------------

def _is_data_url(value: str) -> bool:
    head = value[:256].lower()
    return head.startswith("data:") and ";base64," in head


def _names_a_tool(node: dict, parent_key: str | None) -> bool:
    return (
        parent_key in {"function", "tool_choice", "tools", "functions"}
        or node.get("type") in TOOL_TYPES
        or any(k in node for k in ("input_schema", "parameters", "input", "arguments"))
    )


def scrub_prompt(
    body: Any, scrubber: Scrubber, vault: Vault, *, allow_binary: bool = False
) -> tuple[Any, dict[str, int]]:
    """Redact every string in a request body except its structural fields.

    Message text, system prompts, document blocks, tool inputs and tool-call
    arguments are all scrubbed: personal data in any of them reaches the model
    just the same. ``arguments`` (OpenAI) is a JSON document inside a string,
    so it is parsed and scrubbed field by field. Base64 payloads -- images,
    PDFs, audio, files -- cannot be scrubbed, so they raise ``BinaryContent``
    unless ``allow_binary`` lets them through untouched.
    """
    counts: dict[str, int] = {}

    def scrub_text(text: str) -> str:
        result, _ = scrubber.scrub(text, vault)
        for entity, count in result.counts.items():
            counts[entity] = counts.get(entity, 0) + count
        return result.text

    def binary(where: str, value: Any) -> Any:
        if not allow_binary:
            raise BinaryContent(where)
        return value

    def arguments(value: str) -> str:
        try:
            parsed = json.loads(value)
        except (json.JSONDecodeError, ValueError):
            return scrub_text(value)
        return json.dumps(walk(parsed), ensure_ascii=False)

    def walk(node: Any, key: str | None = None) -> Any:
        if isinstance(node, str):
            if _is_data_url(node):
                return binary(key or "a data: URL", node)
            return scrub_text(node)
        if isinstance(node, list):
            return [walk(item, key) for item in node]
        if not isinstance(node, dict):
            return node
        out: dict[str, Any] = {}
        is_base64_source = node.get("type") == "base64"
        for k, value in node.items():
            if k in STRUCTURAL_KEYS or (k == "name" and _names_a_tool(node, key)):
                out[k] = value
            elif isinstance(value, str) and (
                (k == "data" and is_base64_source) or k in {"file_data", "image_data"}
                or (key == "input_audio" and k == "data")
            ):
                out[k] = binary(f"{key or 'body'}.{k}", value)
            elif k == "arguments" and isinstance(value, str):
                out[k] = arguments(value)
            else:
                out[k] = walk(value, k)
        return out

    return walk(body), counts


def restore_response(body: Any, vault: Vault) -> Any:
    """Put the original values back into anything the model generated."""

    def walk(node: Any, inside_text: bool = False) -> Any:
        if isinstance(node, str):
            return Scrubber.restore(node, vault) if inside_text else node
        if isinstance(node, list):
            return [walk(item, inside_text) for item in node]
        if isinstance(node, dict):
            return {
                key: walk(value, inside_text or key in TEXT_KEYS or key == "delta")
                for key, value in node.items()
            }
        return node

    return walk(body)


class StreamRestorer:
    """Rehydrates a token stream, holding back partial placeholders.

    A placeholder can be split across two deltas -- ``[[PER`` then ``SON_1]]`` --
    and replacing per delta would miss it and leak the marker to the user. Text
    that might be the start of one is held until the next delta resolves it.
    """

    #: The longest prefix worth holding: entity names are short.
    MAX_HOLD = 64
    _PARTIAL = re.compile(r"\[\[?[A-Za-z0-9_:]*$")

    def __init__(self, vault: Vault) -> None:
        self.vault = vault
        self._buffer = ""
        #: The last event that carried text, and the ``event:`` name it came
        #: under: the template for an event that delivers held-back text.
        self.last_event: Any = None
        self.last_event_name: bytes | None = None

    @property
    def holding(self) -> bool:
        return bool(self._buffer)

    def feed(self, text: str) -> str:
        self._buffer += text
        match = self._PARTIAL.search(self._buffer)
        if match and len(self._buffer) - match.start() <= self.MAX_HOLD:
            emit, self._buffer = self._buffer[:match.start()], self._buffer[match.start():]
        else:
            emit, self._buffer = self._buffer, ""
        return Scrubber.restore(emit, self.vault)

    def flush(self) -> str:
        emit, self._buffer = self._buffer, ""
        return Scrubber.restore(emit, self.vault)


def flush_sse_event(restorer: StreamRestorer) -> bytes:
    """Held-back text as a complete event of its own, or ``b""`` if none is held.

    The text held at the end of a stream (an unfinished ``[[``) belongs to the
    last text event, which has already been sent. Writing it bare would put it
    outside any event -- clients drop it or fail to parse -- so it goes out as
    a copy of that last event carrying only the held text.
    """
    if not restorer.holding:
        return b""
    trailing = restorer.flush()
    if restorer.last_event is None:
        return b""
    placed = False

    def fill(node: Any, inside_text: bool = False) -> Any:
        nonlocal placed
        if isinstance(node, str):
            if not inside_text:
                return node
            if placed:
                return ""
            placed = True
            return trailing
        if isinstance(node, list):
            return [fill(item, inside_text) for item in node]
        if isinstance(node, dict):
            return {k: fill(v, inside_text or k in TEXT_KEYS) for k, v in node.items()}
        return node

    event = fill(restorer.last_event)
    head = b"event: " + restorer.last_event_name + b"\n" if restorer.last_event_name else b""
    return head + b"data: " + json.dumps(event).encode() + b"\n\n"


def restore_sse_line(line: bytes, restorer: StreamRestorer) -> bytes:
    """Rehydrate one server-sent-events line, leaving the framing intact."""
    if not line.startswith(b"data:"):
        return line
    payload = line[5:].strip()
    if not payload or payload == b"[DONE]":
        return line
    try:
        event = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return line

    fed = False

    def walk(node: Any, inside_text: bool = False) -> Any:
        nonlocal fed
        if isinstance(node, str):
            if inside_text:
                fed = True
                return restorer.feed(node)
            return node
        if isinstance(node, list):
            return [walk(item, inside_text) for item in node]
        if isinstance(node, dict):
            return {
                key: walk(value, inside_text or key in TEXT_KEYS)
                for key, value in node.items()
            }
        return node

    restored = walk(event)
    if fed:
        restorer.last_event = event
    return b"data: " + json.dumps(restored).encode()


# --------------------------------------------------------------------------
# the server
# --------------------------------------------------------------------------

class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Relay a redirect to the client instead of following it.

    urllib follows a redirect with the request's headers -- the API key among
    them -- to wherever it points, plain http included.
    """

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


_OPENER = urllib.request.build_opener(_NoRedirects)


def _host_of(header: str) -> str:
    """``127.0.0.1:8080`` -> ``127.0.0.1``; ``[::1]:8080`` -> ``::1``."""
    header = header.strip().lower()
    if header.startswith("["):
        return header[1:].split("]", 1)[0]
    return header.rsplit(":", 1)[0] if header.count(":") == 1 else header


def check_upstream(upstream: str) -> str:
    """The upstream URL, if it is https -- or http on this machine -- with no path tricks."""
    parsed = urllib.parse.urlsplit(upstream)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or not host:
        raise ValueError(f"upstream must be an http(s) URL, not {upstream!r}")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("upstream must not carry credentials, a query or a fragment")
    if parsed.scheme == "http" and host not in LOOPBACK_HOSTS:
        raise ValueError(
            f"refusing plain http to {host}: your API key and the redacted prompt would "
            "cross the network unencrypted. Use https (http is allowed to loopback only)."
        )
    return upstream.rstrip("/")


def make_handler(
    scrubber: Scrubber,
    upstream: str,
    stats: ProxyStats,
    *,
    timeout: float = 600.0,
    verbose: bool = False,
    on_report=None,
    allowed_hosts: frozenset[str] | None = LOOPBACK_HOSTS,
    allow_binary: bool = False,
):
    """The request handler. ``allowed_hosts=None`` skips the Host check."""
    upstream = check_upstream(upstream)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "stripii-proxy"

        def log_message(self, fmt: str, *args: Any) -> None:
            # The default handler logs the request line. Paths are fine; bodies
            # and headers never reach a log from here.
            if verbose:
                sys.stderr.write(f"proxy: {fmt % args}\n")

        def _refuse(self, status: int, message: str) -> None:
            body = json.dumps(
                {"type": "error", "error": {"type": "stripii_refused", "message": message}}
            ).encode()
            self._respond(status, body, {"Content-Type": "application/json"})
            self.close_connection = True

        def _admissible(self) -> bool:
            """Refuse a request that must not be forwarded; True if it may be."""
            host = _host_of(self.headers.get("Host") or "")
            if allowed_hosts is not None and host not in allowed_hosts:
                self._refuse(403, "the Host header does not name this proxy")
                return False
            # Appended to the upstream URL, a target such as "@evil.example/" would
            # turn the upstream into credentials and send the key elsewhere.
            if not self.path.startswith("/"):
                self._refuse(400, "the request target must be a path")
                return False
            return True

        def do_GET(self) -> None:
            if not self._admissible():
                return
            if self.path.rstrip("/") in ("/healthz", "/health"):
                payload = json.dumps(
                    {
                        "status": "ok",
                        "upstream": upstream,
                        "profile": scrubber.policy.name,
                        "requests": stats.requests,
                        "redactions": stats.redactions,
                    }
                ).encode()
                self._respond(200, payload, {"Content-Type": "application/json"})
                return
            self._proxy(b"")

        def do_POST(self) -> None:
            if not self._admissible():
                return
            if self.headers.get("Transfer-Encoding"):
                self._refuse(411, "send the body with a Content-Length, not chunked")
                return
            encoding = (self.headers.get("Content-Encoding") or "identity").strip().lower()
            if encoding != "identity":
                self._refuse(415, f"a {encoding}-encoded body cannot be read to be "
                                  "redacted; send it uncompressed")
                return
            raw_length = (self.headers.get("Content-Length") or "0").strip()
            if not raw_length.isdigit():
                self._refuse(400, "invalid Content-Length")
                return
            length = int(raw_length)
            if length > MAX_BODY:
                self._refuse(413, f"the body is larger than {MAX_BODY // (1024 * 1024)} MB")
                return
            self._proxy(self.rfile.read(length) if length else b"")

        # -- plumbing ---------------------------------------------------
        def _respond(self, status: int, body: bytes, headers: dict[str, str]) -> None:
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _forward_headers(self) -> dict[str, str]:
            return {
                key: value
                for key, value in self.headers.items()
                if key.lower() not in HOP_BY_HOP | {"content-type", "content-encoding"}
            }

        def _proxy(self, raw: bytes) -> None:
            vault = Vault()
            body = raw
            wants_stream = False

            if raw:
                # Anything that is not JSON cannot be scrubbed, so it is not sent.
                try:
                    parsed = json.loads(raw.decode("utf-8-sig"))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    self._refuse(415, "the body is not JSON, so it cannot be redacted")
                    return
                try:
                    scrubbed, counts = scrub_prompt(
                        parsed, scrubber, vault, allow_binary=allow_binary
                    )
                except RefusedRequest as refused:
                    self._refuse(refused.status, str(refused))
                    return
                wants_stream = bool(isinstance(scrubbed, dict) and scrubbed.get("stream"))
                body = json.dumps(scrubbed).encode()
                stats.record(counts)
                if on_report is not None:
                    on_report(counts)

            headers = self._forward_headers()
            if body:
                headers["Content-Type"] = "application/json"
            request = urllib.request.Request(
                upstream + self.path,
                data=body or None,
                headers=headers,
                method=self.command,
            )
            try:
                with _OPENER.open(request, timeout=timeout) as response:
                    self._relay(response, vault, wants_stream)
            except urllib.error.HTTPError as error:
                # Upstream errors are relayed as-is; they carry useful detail
                # and contain no redacted content of ours.
                payload = error.read()
                self._respond(
                    error.code,
                    payload,
                    {"Content-Type": error.headers.get("Content-Type", "application/json")},
                )
            except (urllib.error.URLError, TimeoutError, OSError) as error:
                self._respond(
                    502,
                    json.dumps({"error": {"type": "upstream_error", "message": str(error)}}).encode(),
                    {"Content-Type": "application/json"},
                )

        def _relay(self, response, vault: Vault, wants_stream: bool) -> None:
            content_type = response.headers.get("Content-Type", "")
            is_sse = "event-stream" in content_type or wants_stream

            if is_sse:
                self.send_response(response.status)
                self.send_header("Content-Type", content_type or "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                restorer = StreamRestorer(vault)
                event_name: bytes | None = None
                for raw_line in response:
                    line = raw_line.rstrip(b"\r\n")
                    if line.startswith(b"event:"):
                        name = line[6:].strip()
                        # Held text goes out before an event of another kind
                        # (a block or message ending) begins.
                        if restorer.holding and name != restorer.last_event_name:
                            self.wfile.write(flush_sse_event(restorer))
                        event_name = name
                    elif line.startswith(b"data:") and line[5:].strip() == b"[DONE]":
                        self.wfile.write(flush_sse_event(restorer))
                    elif not line:
                        event_name = None
                    out = restore_sse_line(line, restorer)
                    if restorer.last_event is not None and line.startswith(b"data:"):
                        restorer.last_event_name = event_name
                    self.wfile.write(out + b"\n")
                    self.wfile.flush()
                tail = flush_sse_event(restorer)
                if tail:
                    self.wfile.write(b"\n" + tail)
                    self.wfile.flush()
                return

            payload = response.read()
            try:
                restored = json.dumps(restore_response(json.loads(payload), vault)).encode()
            except (json.JSONDecodeError, UnicodeDecodeError):
                restored = payload
            self._respond(
                response.status, restored, {"Content-Type": content_type or "application/json"}
            )

    return Handler


def serve(
    scrubber: Scrubber,
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    upstream: str = DEFAULT_UPSTREAM,
    verbose: bool = False,
    on_report=None,
    allow_binary: bool = False,
) -> ThreadingHTTPServer:
    """Build (but do not start) the proxy server.

    Requests must carry a ``Host`` naming this machine (or ``host`` itself when
    it is a specific non-loopback address); on a wildcard address such as
    ``0.0.0.0`` the check is off, since anything on the network can reach it.
    """
    stats = ProxyStats()
    if host in {"0.0.0.0", "::", ""}:
        allowed: frozenset[str] | None = None
    else:
        allowed = LOOPBACK_HOSTS | {host.strip("[]").lower()}
    handler = make_handler(
        scrubber, upstream, stats, verbose=verbose, on_report=on_report,
        allowed_hosts=allowed, allow_binary=allow_binary,
    )
    server = ThreadingHTTPServer((host, port), handler)
    server.stats = stats  # type: ignore[attr-defined]
    return server
