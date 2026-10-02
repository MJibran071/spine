#!/usr/bin/env python3
"""Exploit-lab long-term memory sidecar (semantic, fully local, no torch).

Free, fully local stack:
  - chromadb PersistentClient (embedded, persists in ./storage)
  - chromadb's built-in ONNX MiniLM embedder (no torch / no
    sentence-transformers — the model is downloaded once by chroma itself,
    in the background warm-up thread, never blocking the hunt)
  - optional Groq LLM enrichment (stdlib-only HTTPS call) at add-time

HTTP API (loopback only):
  GET  /health            -> {"ok": true} once the collection is usable
  POST /add               {"text": str, "metadata": {}}  -> remembers
  POST /search            {"query": str, "limit": 5}     -> {"results": [str]}

Run:  python3 sidecar.py   (port from MEM0_SIDECAR_PORT, default 8765)
The agent's memory.ts starts this automatically when needed; until the
embedding model finishes downloading, /health reports ok=false and the agent
uses its local BM25 memory (localmem.ts) — zero impact on the hunt.
"""
import json
import os
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
PORT = int(os.environ.get("MEM0_SIDECAR_PORT", "8765"))
HERE = os.path.dirname(os.path.abspath(__file__))
STORAGE = os.path.join(HERE, "storage")
COLLECTION = "exploit-lab"
USER_META = "exploit-lab"

_ready = threading.Event()
_collection = None
_lock = threading.Lock()


def groq_key():
    env_path = os.path.join(os.path.dirname(HERE), ".env")
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("GROQ_API_KEY="):
                    return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return os.environ.get("GROQ_API_KEY", "")


def groq_condense(text):
    """One-shot fact condensation via Groq (stdlib urllib, best-effort).
    Returns the original text on any failure — never blocks /add semantics."""
    key = groq_key()
    if not key:
        return text
    try:
        req = urllib.request.Request(
            "https://api.groq.com/openai/v1/chat/completions",
            data=json.dumps({
                "model": "openai/gpt-oss-120b",
                "messages": [
                    {"role": "system", "content": "Rewrite the input as ONE terse third-person memory line (max 60 words). Keep addresses, technique names, and confidence values verbatim. Output only the line."},
                    {"role": "user", "content": text[:1500]},
                ],
                "temperature": 0.1,
                "max_tokens": 120,
            }).encode("utf-8"),
            headers={"content-type": "application/json", "authorization": f"Bearer {key}"},
        )
        with urllib.request.urlopen(req, timeout=20) as r:
            j = json.loads(r.read().decode("utf-8"))
        line = (j.get("choices") or [{}])[0].get("message", {}).get("content", "").strip()
        return line if len(line) >= 10 else text
    except Exception:
        return text


def init_collection():
    """Blocking init: import chromadb, open/create the collection. Called from
    the warm-up thread; /health flips true once this succeeds."""
    global _collection
    import chromadb  # lazy: keeps /health responsive during first import

    client = chromadb.PersistentClient(path=STORAGE)
    _collection = client.get_or_create_collection(
        COLLECTION, metadata={"hnsw:space": "cosine"}
    )
    _ready.set()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # quiet — the daemon log is the real log
        pass

    def _json(self, code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/health"):
            if _ready.is_set():
                self._json(200, {"ok": True, "count": _collection.count()})
            else:
                self._json(200, {"ok": False, "error": "warming up (model download or import)"})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            self._json(400, {"error": "bad json"})
            return
        if not _ready.is_set():
            self._json(503, {"error": "not ready — caller should fall back to local memory"})
            return
        try:
            with _lock:
                if self.path.startswith("/add"):
                    text = str(req.get("text", "")).strip()
                    if not text:
                        self._json(400, {"error": "empty text"})
                        return
                    meta = req.get("metadata") or {}
                    meta = {k: str(v) for k, v in meta.items() if v is not None}
                    meta["t"] = str(meta.get("t") or time.strftime("%Y-%m-%d"))
                    stored = groq_condense(text)
                    _collection.add(
                        ids=[f"{time.time_ns()}"],
                        documents=[stored[:800]],
                        metadatas=[meta],
                    )
                    self._json(200, {"ok": True})
                elif self.path.startswith("/search"):
                    query = str(req.get("query", "")).strip()
                    limit = max(1, min(int(req.get("limit", 5)), 20))
                    if not query or _collection.count() == 0:
                        self._json(200, {"results": []})
                        return
                    res = _collection.query(query_texts=[query], n_results=limit)
                    docs = (res.get("documents") or [[]])[0]
                    self._json(200, {"results": [d[:500] for d in docs]})
                else:
                    self._json(404, {"error": "not found"})
        except Exception as e:
            self._json(500, {"error": str(e)[:300]})


if __name__ == "__main__":
    os.makedirs(STORAGE, exist_ok=True)

    def warm_up():
        init_collection()
        # First embed triggers chroma's one-time ONNX model download (~80MB).
        # Do it here, in the background, so the first real add/search isn't the
        # one stuck waiting on it.
        try:
            _collection.query(query_texts=["warmup"], n_results=1)
        except Exception as e:
            print(f"[memory-sidecar] warm-up embed failed (will retry on demand): {e}", flush=True)
        print("[memory-sidecar] collection + embedder ready", flush=True)

    threading.Thread(target=warm_up, daemon=True).start()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"[memory-sidecar] listening on {HOST}:{PORT} (storage: {STORAGE})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)
