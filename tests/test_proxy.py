"""The local proxy: redacted on the way out, restored on the way back.

Every test runs against a fake upstream on loopback, which records exactly what
it received. That is the only way to prove the claim that matters -- not "the
client got a sensible answer" but "the upstream never saw the name".
"""

from __future__ import annotations

import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from stripii import Scrubber, Vault, get_profile
from stripii.proxy import (
    StreamRestorer,
    restore_response,
    restore_sse_line,
    scrub_prompt,
    serve,
)


class Upstream:
    """A stand-in model API that records what it was sent."""

    def __init__(self, reply=None, sse_lines=None, status=200):
        self.received: list[dict] = []
        self.headers: list[dict] = []
        self.reply = reply or {"content": [{"type": "text", "text": "ok"}]}
        self.sse_lines = sse_lines
        self.status = status
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b"{}"
                outer.received.append(json.loads(raw))
                outer.headers.append(dict(self.headers))

                if outer.sse_lines is not None:
                    body = b"\n".join(outer.sse_lines) + b"\n"
                    self.send_response(outer.status)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

                body = json.dumps(outer.reply).encode()
                self.send_response(outer.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


class Proxy:
    def __init__(self, upstream_url: str, profile: str = "health", allow_binary: bool = False):
        self.server = serve(
            Scrubber(get_profile(profile)),
            host="127.0.0.1",
            port=0,
            upstream=upstream_url,
            allow_binary=allow_binary,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


def post(url: str, payload: dict, headers: dict | None = None):
    request = urllib.request.Request(
        url + "/v1/messages",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.status, response.read()


PROMPT = "Patient Margaret Whitfield, MRN 4471982, was seen. Glucose 142 mg/dL."


# --------------------------------------------------------------------------
# the round trip
# --------------------------------------------------------------------------

def test_the_upstream_never_sees_the_identifiers():
    with Upstream() as upstream, Proxy(upstream.url) as proxy:
        post(proxy.url, {"model": "m", "messages": [{"role": "user", "content": PROMPT}]})

    sent = json.dumps(upstream.received[0])
    assert "Margaret Whitfield" not in sent
    assert "4471982" not in sent
    assert "[[PERSON_1]]" in sent
    # and the clinical content is still there to reason about
    assert "Glucose 142 mg/dL" in sent


def test_the_reply_is_rehydrated_for_the_client():
    reply = {"content": [{"type": "text", "text": "[[PERSON_1]] has a high [[MRN_1]] record."}]}
    with Upstream(reply=reply) as upstream, Proxy(upstream.url) as proxy:
        _, body = post(
            proxy.url, {"model": "m", "messages": [{"role": "user", "content": PROMPT}]}
        )

    text = json.loads(body)["content"][0]["text"]
    assert "Margaret Whitfield" in text
    assert "4471982" in text
    assert "[[" not in text


def test_non_prompt_fields_are_left_alone():
    """Model names and parameters must survive untouched."""
    with Upstream() as upstream, Proxy(upstream.url) as proxy:
        post(
            proxy.url,
            {
                "model": "claude-opus-5",
                "max_tokens": 1024,
                "temperature": 0.2,
                "messages": [{"role": "user", "content": PROMPT}],
            },
        )
    sent = upstream.received[0]
    assert sent["model"] == "claude-opus-5"
    assert sent["max_tokens"] == 1024
    assert sent["temperature"] == 0.2
    assert sent["messages"][0]["role"] == "user"


def test_structured_content_blocks_are_handled():
    payload = {
        "model": "m",
        "system": "You help with records for Margaret Whitfield.",
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": PROMPT}]},
        ],
    }
    with Upstream() as upstream, Proxy(upstream.url) as proxy:
        post(proxy.url, payload)
    sent = upstream.received[0]
    assert "Margaret Whitfield" not in json.dumps(sent)
    assert sent["messages"][0]["content"][0]["type"] == "text"


def test_auth_headers_are_forwarded():
    with Upstream() as upstream, Proxy(upstream.url) as proxy:
        post(
            proxy.url,
            {"model": "m", "messages": [{"role": "user", "content": "hello"}]},
            headers={"x-api-key": "sk-test-key", "anthropic-version": "2023-06-01"},
        )
    received = {k.lower(): v for k, v in upstream.headers[0].items()}
    assert received["x-api-key"] == "sk-test-key"
    assert received["anthropic-version"] == "2023-06-01"


def test_upstream_errors_are_relayed():
    with Upstream(reply={"error": "bad request"}, status=400) as upstream, Proxy(
        upstream.url
    ) as proxy:
        with pytest.raises(urllib.error.HTTPError) as excinfo:
            post(proxy.url, {"model": "m", "messages": [{"role": "user", "content": "x"}]})
        assert excinfo.value.code == 400


def test_an_unreachable_upstream_gives_502():
    # Port 1 on loopback will refuse the connection.
    with Proxy("http://127.0.0.1:1") as proxy:
        with pytest.raises(urllib.error.HTTPError) as excinfo:
            post(proxy.url, {"model": "m", "messages": [{"role": "user", "content": "x"}]})
        assert excinfo.value.code == 502


def test_health_endpoint_reports_status():
    with Upstream() as upstream, Proxy(upstream.url) as proxy, urllib.request.urlopen(
        proxy.url + "/healthz", timeout=10
    ) as response:
        payload = json.loads(response.read())
    assert payload["status"] == "ok"
    assert payload["profile"] == "health"


def test_a_non_json_body_is_refused_not_forwarded():
    with Upstream() as upstream, Proxy(upstream.url) as proxy:
        request = urllib.request.Request(
            proxy.url + "/v1/messages",
            data=b"Patient Margaret Whitfield SSN 219-09-9999", method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as excinfo:
            urllib.request.urlopen(request, timeout=10)
    assert excinfo.value.code == 415
    assert upstream.received == []


# --------------------------------------------------------------------------
# streaming
# --------------------------------------------------------------------------

def test_streamed_text_is_rehydrated():
    lines = [
        b'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hi [[PERSON_1]]"}}',
        b'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":", record [[MRN_1]]."}}',
        b"data: [DONE]",
    ]
    with Upstream(sse_lines=lines) as upstream, Proxy(upstream.url) as proxy:
        _, body = post(
            proxy.url,
            {"model": "m", "stream": True, "messages": [{"role": "user", "content": PROMPT}]},
        )
    text = body.decode()
    assert "Margaret Whitfield" in text
    assert "4471982" in text


def test_a_placeholder_split_across_deltas_is_still_restored():
    """The failure this guards: replacing per delta misses a split marker."""
    vault = Vault()
    vault.placeholder_for("PERSON", "Margaret Whitfield", "[[{entity}_{n}]]")
    restorer = StreamRestorer(vault)

    out = restorer.feed("Hello [[PER") + restorer.feed("SON_1]], welcome") + restorer.flush()
    assert out == "Hello Margaret Whitfield, welcome"
    assert "[[" not in out


def test_the_stream_restorer_does_not_hold_ordinary_brackets():
    vault = Vault()
    restorer = StreamRestorer(vault)
    assert restorer.feed("an array [1, 2, 3] here") + restorer.flush() == (
        "an array [1, 2, 3] here"
    )


def test_sse_framing_survives_rehydration():
    vault = Vault()
    vault.placeholder_for("PERSON", "Jane Smith", "[[{entity}_{n}]]")
    restorer = StreamRestorer(vault)
    line = b'data: {"delta":{"text":"[[PERSON_1]] said"}}'
    out = restore_sse_line(line, restorer) + restorer.flush().encode()
    assert out.startswith(b"data: ")
    assert b"Jane Smith" in out


@pytest.mark.parametrize("line", [b"event: ping", b"", b"data: [DONE]", b"data: not-json"])
def test_non_payload_sse_lines_pass_through(line):
    restorer = StreamRestorer(Vault())
    assert restore_sse_line(line, restorer) == line


# --------------------------------------------------------------------------
# the body walkers, directly
# --------------------------------------------------------------------------

def test_scrub_prompt_counts_what_it_redacted():
    scrubber = Scrubber(get_profile("health"))
    body, counts = scrub_prompt(
        {"model": "m", "messages": [{"role": "user", "content": PROMPT}]},
        scrubber,
        Vault(),
    )
    assert counts.get("PERSON") == 1
    assert body["model"] == "m"


def test_scrub_prompt_ignores_a_non_dict_body():
    scrubber = Scrubber(get_profile("health"))
    body, counts = scrub_prompt(["a", "b"], scrubber, Vault())
    assert body == ["a", "b"]
    assert counts == {}


def test_restore_response_only_touches_generated_text():
    vault = Vault()
    vault.placeholder_for("PERSON", "Jane Smith", "[[{entity}_{n}]]")
    restored = restore_response(
        {"model": "[[PERSON_1]]", "content": [{"type": "text", "text": "[[PERSON_1]]"}]},
        vault,
    )
    # a model identifier is not generated text and must not be rewritten
    assert restored["model"] == "[[PERSON_1]]"
    assert restored["content"][0]["text"] == "Jane Smith"


# --------------------------------------------------------------------------
# nothing reaches the upstream unredacted
# --------------------------------------------------------------------------

SECRETS = ("Margaret Whitfield", "219-09-9999")
LEAKY = "Patient Name: Margaret Whitfield SSN 219-09-9999"


def _leaks(received) -> list[str]:
    sent = json.dumps(received)
    return [value for value in SECRETS if value in sent]


@pytest.mark.parametrize(
    "payload",
    [
        # an Anthropic plain-text document block
        {"model": "m", "messages": [{"role": "user", "content": [{"type": "document", "source": {
            "type": "text", "media_type": "text/plain", "data": LEAKY}}]}]},
        # a tool call in the history, and its result
        {"model": "m", "messages": [
            {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "lookup",
                                               "input": {"patient": "Margaret Whitfield",
                                                         "ssn": "219-09-9999"}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1",
                                          "content": LEAKY}]}]},
        # OpenAI tool-call arguments: JSON inside a string
        {"model": "m", "messages": [{"role": "assistant", "content": None, "tool_calls": [{
            "id": "c1", "type": "function", "function": {
                "name": "f", "arguments": json.dumps({"patient": "Margaret Whitfield",
                                                      "ssn": "219-09-9999"})}}]}]},
        # OpenAI Responses input, a chat message's participant name, metadata
        {"model": "m", "input": [{"role": "user", "content": [{"type": "input_text", "text": LEAKY}]}]},
        {"model": "m", "messages": [{"role": "user", "name": "Margaret Whitfield", "content": "hi"}]},
        {"model": "m", "metadata": {"note": LEAKY}, "messages": []},
        # a list at the top level
        [{"role": "user", "content": LEAKY}],
    ],
)
def test_every_content_field_is_scrubbed(payload):
    with Upstream() as upstream, Proxy(upstream.url) as proxy:
        post(proxy.url, payload)
    assert _leaks(upstream.received[0]) == []


def test_structure_the_api_needs_is_left_exactly_as_sent():
    payload = {
        "model": "claude-x", "tool_choice": {"type": "tool", "name": "lookup_patient"},
        "tools": [{"name": "lookup_patient", "description": "Find a patient",
                   "input_schema": {"type": "object", "required": ["ssn"],
                                    "properties": {"ssn": {"type": "string"}}}}],
        "messages": [{"role": "assistant", "content": [{
            "type": "tool_use", "id": "toolu_01", "name": "lookup_patient",
            "input": {"ssn": "219-09-9999"}}]}],
    }
    with Upstream() as upstream, Proxy(upstream.url) as proxy:
        post(proxy.url, payload)
    sent = upstream.received[0]
    assert sent["tools"] == payload["tools"]
    assert sent["tool_choice"] == payload["tool_choice"]
    block = sent["messages"][0]["content"][0]
    assert (block["type"], block["id"], block["name"]) == ("tool_use", "toolu_01", "lookup_patient")
    assert "219-09-9999" not in json.dumps(block["input"])
    assert json.loads(json.dumps(sent))   # still valid JSON throughout


def test_tool_call_arguments_stay_a_json_string():
    payload = {"model": "m", "messages": [{"role": "assistant", "tool_calls": [{
        "id": "c1", "type": "function", "function": {
            "name": "f", "arguments": json.dumps({"ssn": "219-09-9999", "n": 3})}}]}]}
    with Upstream() as upstream, Proxy(upstream.url) as proxy:
        post(proxy.url, payload)
    function = upstream.received[0]["messages"][0]["tool_calls"][0]["function"]
    assert function["name"] == "f"
    arguments = json.loads(function["arguments"])
    assert arguments["n"] == 3 and "219-09-9999" not in arguments["ssn"]


BINARY_PAYLOADS = [
    {"model": "m", "messages": [{"role": "user", "content": [{"type": "image", "source": {
        "type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo="}}]}]},
    {"model": "m", "messages": [{"role": "user", "content": [{"type": "document", "source": {
        "type": "base64", "media_type": "application/pdf", "data": "JVBERi0xLjQ="}}]}]},
    {"model": "m", "messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {
        "url": "data:image/png;base64,iVBORw0KGgo="}}]}]},
    {"model": "m", "input": [{"role": "user", "content": [{"type": "input_file",
                                                           "file_data": "JVBERi0xLjQ="}]}]},
]


@pytest.mark.parametrize("payload", BINARY_PAYLOADS)
def test_base64_content_is_refused_unless_allowed(payload):
    with Upstream() as upstream, Proxy(upstream.url) as proxy:
        with pytest.raises(urllib.error.HTTPError) as excinfo:
            post(proxy.url, payload)
        assert excinfo.value.code == 400
        assert b"allow-binary-uploads" in excinfo.value.read()
    assert upstream.received == []

    with Upstream() as upstream, Proxy(upstream.url, allow_binary=True) as proxy:
        post(proxy.url, payload)
    assert upstream.received[0] == payload


def _raw(proxy, method="POST", path="/v1/messages", body=b"{}", headers=None, host=None):
    import http.client

    port = proxy.server.server_address[1]
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    connection.putrequest(method, path, skip_host=host is not None,
                          skip_accept_encoding=True)
    if host is not None:
        connection.putheader("Host", host)
    for key, value in (headers or {}).items():
        connection.putheader(key, value)
    if "Content-Length" not in (headers or {}):
        connection.putheader("Content-Length", str(len(body)))
    connection.endheaders(body)
    response = connection.getresponse()
    return response.status, response.read()


def test_a_compressed_body_is_refused():
    import gzip

    body = gzip.compress(json.dumps({"model": "m", "messages": [
        {"role": "user", "content": LEAKY}]}).encode())
    with Upstream() as upstream, Proxy(upstream.url) as proxy:
        status, _ = _raw(proxy, body=body, headers={"Content-Encoding": "gzip",
                                                    "Content-Type": "application/json"})
    assert status == 415
    assert upstream.received == []


@pytest.mark.parametrize("host", ["attacker.example", "attacker.example:8080", "10.0.0.5", ""])
def test_a_foreign_host_header_is_refused(host):
    """What a page using DNS rebinding sends to a proxy on loopback."""
    with Upstream() as upstream, Proxy(upstream.url) as proxy:
        status, _ = _raw(proxy, host=host)
        assert _raw(proxy, method="GET", path="/healthz", body=b"", host=host)[0] == 403
    assert status == 403
    assert upstream.received == []


@pytest.mark.parametrize("host", ["127.0.0.1:8080", "localhost", "localhost:1234", "[::1]:8080"])
def test_loopback_host_headers_are_accepted(host):
    with Upstream() as upstream, Proxy(upstream.url) as proxy:
        status, _ = _raw(proxy, host=host)
    assert status == 200


@pytest.mark.parametrize(("length", "status"), [("-1", 400), ("abc", 400),
                                                (str(64 * 1024 * 1024), 413)])
def test_a_bad_or_huge_content_length_is_refused(length, status):
    with Upstream() as upstream, Proxy(upstream.url) as proxy:
        assert _raw(proxy, headers={"Content-Length": length})[0] == status
    assert upstream.received == []


def test_a_request_target_cannot_redirect_the_upstream():
    """``http://127.0.0.1:N`` + ``@evil:M/v1`` would make the upstream a credential."""
    with Upstream() as upstream, Upstream() as evil, Proxy(upstream.url) as proxy:
        port = evil.server.server_address[1]
        status, _ = _raw(proxy, path=f"@127.0.0.1:{port}/v1/messages",
                         headers={"x-api-key": "sk-test-key"})
    assert status == 400
    assert evil.received == [] and upstream.received == []


@pytest.mark.parametrize("url", ["http://api.anthropic.com", "http://10.0.0.5:8080",
                                 "ftp://127.0.0.1", "https://user:pw@api.example.com"])
def test_an_upstream_that_is_not_https_is_refused(url):
    with pytest.raises(ValueError):
        serve(Scrubber(get_profile("health")), port=0, upstream=url)


def test_redirects_are_relayed_not_followed():
    class Redirecting(Upstream):
        def __init__(self, target):
            super().__init__()
            self.server.server_close()     # replaced by one that redirects
            outer = self

            class Handler(BaseHTTPRequestHandler):
                protocol_version = "HTTP/1.1"

                def log_message(self, *args):
                    pass

                def do_POST(self):
                    self.rfile.read(int(self.headers.get("Content-Length") or 0))
                    outer.received.append({})
                    self.send_response(307)
                    self.send_header("Location", target + "/v1/messages")
                    self.send_header("Content-Length", "0")
                    self.end_headers()

            self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    with Upstream() as elsewhere, Redirecting(elsewhere.url) as upstream, \
            Proxy(upstream.url) as proxy:
        status, _ = _raw(proxy, headers={"x-api-key": "sk-test-key"})
    assert status == 307
    assert elsewhere.received == []


def test_held_back_text_at_the_end_of_a_stream_is_a_well_formed_event():
    lines = [
        b"event: content_block_delta",
        b'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"see [[PER"}}',
        b"",
        b"event: content_block_stop",
        b'data: {"type":"content_block_stop"}',
        b"",
    ]
    with Upstream(sse_lines=lines) as upstream, Proxy(upstream.url) as proxy:
        _, body = post(proxy.url, {"model": "m", "stream": True,
                                   "messages": [{"role": "user", "content": "hi"}]})
    events = [e for e in body.decode().split("\n\n") if e.strip()]
    texts = []
    for event in events:
        lines_ = event.strip().splitlines()
        # every line belongs to an event: no bare text between them
        assert all(line.startswith(("event:", "data:")) for line in lines_), event
        for line in lines_:
            if line.startswith("data:"):
                texts.append(json.loads(line[5:]).get("delta", {}).get("text", ""))
    assert "".join(texts) == "see [[PER"
    # and the held text arrived before the block was closed
    assert events[-1].startswith("event: content_block_stop")


def test_held_back_text_is_flushed_before_done_in_an_openai_stream():
    lines = [
        b'data: {"choices":[{"delta":{"content":"array ["}}]}',
        b"",
        b"data: [DONE]",
        b"",
    ]
    with Upstream(sse_lines=lines) as upstream, Proxy(upstream.url) as proxy:
        _, body = post(proxy.url, {"model": "m", "stream": True,
                                   "messages": [{"role": "user", "content": "hi"}]})
    text = body.decode()
    data = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")]
    assert data[-1] == "[DONE]"
    content = "".join(json.loads(d)["choices"][0]["delta"]["content"] for d in data[:-1])
    assert content == "array ["
    assert all(line.startswith("data:") or not line for line in text.splitlines())
