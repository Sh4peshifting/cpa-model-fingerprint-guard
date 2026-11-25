"""Run the real CLIProxyAPI plugin ABI against two loopback-only Kimi fixtures."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection
from http.cookies import SimpleCookie
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


MANAGEMENT_KEY = "fixture-management-only"
CLIENT_KEY = "fixture-client-only"
API = "/v0/management/model-fingerprint-guard"
RESOURCE = "/v0/resource/plugins/model-fingerprint-guard"
MODEL = "kimi-k3"


class Upstream(BaseHTTPRequestHandler):
    calls = []
    failures = set()
    sse_faults = set()

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        auth = self.headers.get("Authorization", "")
        probe = any(len(str(item.get("content", ""))) > 80 for item in body.get("messages", []))
        model = body.get("model")
        self.calls.append((auth, model, probe))
        if body.get("stream") and auth in self.sse_faults:
            events = [
                'data: {"id":"chatcmpl-fixture","object":"chat.completion.chunk","created":1,"model":"k3","choices":[{"index":0,"delta":{"content":"sample"},"finish_reason":null}]}\n\n',
                'event: error\ndata: {"type":"error","error":{"code":"server_is_overloaded","message":"Our servers are currently overloaded. Please try again later."}}\n\n',
                'data: [DONE]\n\n',
            ]
            data = "".join(events).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if auth in self.failures:
            status = 503
            result = {"error": {"code": "server_is_overloaded", "message": "Our servers are currently overloaded. Please try again later."}}
        else:
            status = 200
            result = {
                "id": "chatcmpl-fixture", "object": "chat.completion", "created": 1,
                "model": model,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "1, 2"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 2, "completion_tokens": 2, "total_tokens": 4},
            }
        data = json.dumps(result).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, _format, *_args):
        pass


def available_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(base, path, method="GET", payload=None, key=MANAGEMENT_KEY):
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = Request(base + path, data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=8) as response:
            return response.status, response.read()
    except HTTPError as response:
        return response.code, response.read()


def wait_for(fn, timeout=16):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        try:
            result = fn()
            if result:
                return result
        except (URLError, TimeoutError, ConnectionError):
            pass
        time.sleep(0.2)
    raise AssertionError("Timed out waiting for the pinned host")


@contextmanager
def run_host(binary, directory, flags=()):
    logfile = directory / "host.log"
    with logfile.open("w+") as log:
        env = {name: os.environ[name] for name in ("PATH", "SYSTEMROOT", "WINDIR") if name in os.environ}
        env.update(HTTP_PROXY="http://127.0.0.1:1", HTTPS_PROXY="http://127.0.0.1:1",
                   NO_PROXY="127.0.0.1,localhost")
        process = subprocess.Popen(
            [binary, "-config", str(directory / "host.yaml"), "-local-model", *flags],
            cwd=directory, env=env, stdout=log, stderr=log,
        )
        try:
            yield
        except BaseException:
            log.seek(0)
            print("\n".join(line for line in log.read().splitlines() if "/state" not in line)[-10000:])
            raise
        finally:
            process.terminate()
            try:
                process.wait(15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(5)


@contextmanager
def run_access_proxy(origin_port):
    """Require a browser session cookie before forwarding the login request."""
    class AccessProxy(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == API + "/state":
                cookie = SimpleCookie(self.headers.get("Cookie", "")).get("CF_Authorization")
                if not cookie or cookie.value != "fixture-access-session":
                    self.send_response(302)
                    self.send_header("Location", "/access/login")
                    self.end_headers()
                    return
            connection = HTTPConnection("127.0.0.1", origin_port, timeout=8)
            try:
                headers = {"Authorization": self.headers["Authorization"]} if "Authorization" in self.headers else {}
                connection.request("GET", self.path, headers=headers)
                response = connection.getresponse()
                body = response.read()
                self.send_response(response.status)
                for name in ("Content-Type", "Content-Security-Policy", "Cache-Control", "Referrer-Policy", "X-Content-Type-Options"):
                    if (value := response.getheader(name)) is not None:
                        self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            finally:
                connection.close()

        def log_message(self, _format, *_args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), AccessProxy) as proxy:
        thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{proxy.server_port}"
        finally:
            proxy.shutdown()
            thread.join(timeout=5)


def get_state(base):
    code, body = request(base, API + "/state")
    if code == 200:
        return json.loads(body)
    return None


def main():
    args = argparse.ArgumentParser()
    args.add_argument("--host", type=Path, required=True)
    args.add_argument("--plugin", type=Path, required=True)
    args.add_argument("--browser-test", action="store_true")
    opts = args.parse_args()
    host, plugin = opts.host.resolve(), opts.plugin.resolve()
    with tempfile.TemporaryDirectory(prefix="mfg-host-") as temp, ThreadingHTTPServer(("127.0.0.1", 0), Upstream) as upstream:
        tmp = Path(temp)
        (tmp / "plugins").mkdir()
        (tmp / "auth").mkdir()
        shutil.copy(plugin, tmp / "plugins" / plugin.name)
        th = threading.Thread(target=upstream.serve_forever, daemon=True)
        th.start()
        try:
            test_host(host, tmp, upstream.server_port, opts.browser_test)
        finally:
            upstream.shutdown()
            th.join(timeout=5)


def test_host(host, tmp, upstream_port, browser_test):
    host_port = available_port()
    base = f"http://127.0.0.1:{host_port}"
    expires = (datetime.now(timezone.utc) + timedelta(days=8)).isoformat()
    for id, priority in (("a", 20), ("b", 10)):
        (tmp / "auth" / f"fixture-{id}.json").write_text(json.dumps({
            "type": "kimi", "access_token": f"fixture-upstream-{id}", "refresh_token": f"fixture-refresh-{id}",
            "email": f"fixture-{id}@invalid", "expired": expires, "priority": priority,
            "base_url": f"http://127.0.0.1:{upstream_port}",
            "note": "fixture private note",
        }))
    (tmp / "host.yaml").write_text(f"""
config-version: 8
server:
  host: 127.0.0.1
  port: {host_port}
management:
  allow-remote: false
  secret-key: {MANAGEMENT_KEY}
  disable-control-panel: true
access:
  api-keys: [{CLIENT_KEY}]
oauth:
  auth-dir: "{(tmp / "auth").as_posix()}"
routing:
  retry:
    request-retry: 0
plugins:
  enabled: true
  dir: "{(tmp / "plugins").as_posix()}"
  configs:
    model-fingerprint-guard:
      enabled: true
      native-diagnostics: true
      reference-auto-update: false
      state-dir: "{(tmp / "state").as_posix()}"
      settings:
        enabled: true
        default:
          idle: false
          model: {MODEL}
          expected: {MODEL}
        scan_seconds: 1
        retry_seconds: 30
        jitter_seconds: 0
""")
    with run_host(host, tmp):
        initial = wait_for(lambda: next((s for s in [get_state(base)] if s and len(s["auths"]) == 2), None))
        auths = {a["name"]: a for a in initial["auths"]}
        a, b = auths["fixture-a.json"]["id"], auths["fixture-b.json"]["id"]
        assert all(x["probeable"] for x in auths.values()), initial
        assert request(base, API + "/state", key=None)[0] in {401, 403}
        assert request(base, API + "/action", "POST", {"action": "isolate", "ids": [a]}, key="wrong")[0] in {401, 403}
        page_status, page = request(base, RESOURCE + "/index.html", key=None)
        assert page_status == 200 and "模型指纹守卫".encode() in page, (page_status, page[:100])
        assert request(base, RESOURCE + "/app.js", key=None)[0] == 200
        plugins_status, plugins = request(base, "/v0/management/plugins")
        assert plugins_status == 200 and RESOURCE.encode() in plugins
        serialized = json.dumps(initial)
        assert all(secret not in serialized for secret in ["fixture-upstream", "fixture-refresh", "fixture private note", MANAGEMENT_KEY])
        revision = initial["revision"]
        assert request(base, API + "/settings", "PUT", {"revision": revision, "settings": {"scan_seconds": 0}})[0] == 400
        assert request(base, API + "/auth-settings", "PUT", {"revision": revision, "auths": {a: {"idle": False}}})[0] == 200

        # The host may persist inference verification on the first business success.
        # Let the watcher publish that new credential snapshot before probing.
        assert call_business(base)[0] == 200
        time.sleep(1.5)
        before_probe = wait_for(lambda: next((item for item in get_state(base)["auths"]
                                             if item["id"] == a and item.get("last_business") and not item.get("active")), None))
        Upstream.calls.clear()
        code, body = request(base, API + "/action", "POST", {"action": "check", "ids": [a]})
        assert code == 200 and json.loads(body)["results"][a] == "", (code, body)
        try:
            after_probe = wait_for(lambda: next((s for s in [get_state(base)] if s and s["history"]), None))
        except AssertionError:
            current = get_state(base)
            print("probe diagnostics", current and current["auths"], Upstream.calls)
            raise
        assert after_probe["history"][0]["result"]["status"] == "inconclusive", after_probe["history"][0]
        assert next(x for x in after_probe["auths"] if x["id"] == a)["last_business"] == before_probe["last_business"]
        assert len(Upstream.calls) == 3 and all(auth == "Bearer fixture-upstream-a" and model == "k3" and probe
                                               for auth, model, probe in Upstream.calls), Upstream.calls

        Upstream.failures.add("Bearer fixture-upstream-a")
        call_business(base)
        isolated = wait_for(lambda: next((s for s in [get_state(base)] if s and any(
            x["id"] == a and x["isolated"] for x in s["auths"])), None))
        assert not next(x for x in isolated["auths"] if x["id"] == b)["isolated"]
        assert next(x for x in isolated["auths"] if x["id"] == a).get("last_business")
        call_count = len(Upstream.calls)
        assert call_business(base)[0] == 200
        assert any(auth == "Bearer fixture-upstream-b" and not probe for auth, _, probe in Upstream.calls[call_count:])
        overloaded = wait_for(lambda: next((row for row in get_state(base)["history"]
                                            if row["trigger"].get("http_status") == 503), None))
        assert overloaded["result"]["status"] == "transient"
        assert not any(auth == "Bearer fixture-upstream-a" and probe for auth, _, probe in Upstream.calls[call_count:])
        if browser_test:
            script = Path(__file__).with_name("browser.mjs")
            with run_access_proxy(host_port) as access_base:
                subprocess.run(["node", str(script), base, access_base], check=True, timeout=40)
    with run_host(host, tmp):
        restored = wait_for(lambda: next((s for s in [get_state(base)] if s and len(s["auths"]) == 2), None))
        assert any(x["id"] == a and x["isolated"] for x in restored["auths"])
        assert call_business(base)[0] == 200
        assert Upstream.calls[-1][0] == "Bearer fixture-upstream-b"
        Upstream.sse_faults.add("Bearer fixture-upstream-b")
        status, stream = call_business(base, stream=True)
        assert status == 200, (status, stream[:120])
        assert b"server_is_overloaded" in stream, stream[:500]
        sse = wait_for(lambda: next((item for item in get_state(base)["auths"]
                                     if item["id"] == b and item["isolated"]), None))
        assert sse["trigger"]["error_code"] == "server_is_overloaded", sse
        code, body = request(base, API + "/action", "POST", {"action": "release", "ids": [a]})
        assert code == 200 and json.loads(body)["results"][a] == "", (code, body)
    print("Pinned CLIProxyAPI: plugin ABI, management authorization, three pinned challenges, HTTP 503 cooldown, SSE overload isolation and restart passed")


def call_business(base, stream=False):
    return request(base, "/v1/chat/completions", "POST", {
        "model": MODEL, "stream": stream, "messages": [{"role": "user", "content": "hello"}],
    }, CLIENT_KEY)


if __name__ == "__main__":
    main()
