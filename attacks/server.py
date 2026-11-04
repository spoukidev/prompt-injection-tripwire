"""Mock attacker / content web server.

Serves the poisoned pages from ``attacks/corpus`` and the benign pages from
``attacks/benign`` for ``*.test`` hosts. In Docker it runs as its own service and
the sandboxed ``fetch_url`` tool reaches it at ``/site/{host}/{path}``; in-process
the benchmark calls :func:`render_url` directly. It never contacts the internet.

    uvicorn attacks.server:app --port 8081
"""

from __future__ import annotations

import html
import json
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent


def _jsonl(*paths: Path) -> list[dict]:
    rows = []
    for p in paths:
        if p.exists():
            with open(p, encoding="utf-8") as fh:
                rows += [json.loads(line) for line in fh if line.strip()]
    return rows


@lru_cache(maxsize=1)
def load_attacks() -> list[dict]:
    """Main corpus + hold-out set (each row has ``split``: main | holdout)."""
    return _jsonl(ROOT / "corpus" / "payloads.jsonl", ROOT / "corpus" / "holdout.jsonl")


@lru_cache(maxsize=1)
def load_benign() -> list[dict]:
    return _jsonl(ROOT / "benign" / "benign.jsonl", ROOT / "benign" / "holdout.jsonl")


def attack_url(a: dict) -> str:
    return f"https://{a['site']}/posts/{a['id']}"


def benign_url(b: dict) -> str:
    return f"https://{b['site']}/{b['slug']}"


def _page(title: str, body_html: str) -> str:
    return (f"<!doctype html>\n<html><head><title>{html.escape(title)}</title></head>\n<body>\n<article>\n"
            f"<h1>{html.escape(title)}</h1>\n{body_html}\n</article>\n</body></html>\n")


def render_attack_page(a: dict) -> str:
    p1, p2 = (f"<p>{html.escape(f)}</p>" for f in a["filler"])
    payload = a["payload"]
    # Payloads that already are HTML are inserted raw; plain-text payloads go in a paragraph.
    block = payload if payload.lstrip().startswith("<") else f"<p>{payload}</p>"
    return _page(a["title"], f"{p1}\n{block}\n{p2}")


def render_benign_page(b: dict) -> str:
    paras = "\n".join(p if p.startswith("![") else f"<p>{html.escape(p)}</p>" for p in b["content"])
    if b.get("link"):
        paras += f'\n<p><a href="{html.escape(b["link"])}">Read more</a></p>'
    return _page(b["title"], paras)


@lru_cache(maxsize=1)
def _index() -> dict[str, str]:
    idx: dict[str, str] = {}
    for a in load_attacks():
        if a["carrier"] == "web":
            idx[attack_url(a)] = render_attack_page(a)
    for b in load_benign():
        if b["kind"] == "web":
            idx[benign_url(b)] = render_benign_page(b)
    return idx


def render_url(url: str) -> str:
    """Return the HTML for a *.test URL (unknown paths get a small generic page)."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if not host.endswith(".test"):
        raise ValueError("only *.test hosts are served")
    key = f"https://{host}{parts.path}"
    if key in _index():
        return _index()[key]
    return _page(f"{host}{parts.path}", "<p>This is the linked page. It contains the full article text.</p>")


# ------------------------------------------------------------------ HTTP app
try:
    from fastapi import FastAPI, Request
    from fastapi.responses import HTMLResponse, JSONResponse

    app = FastAPI(title="Tripwire mock attacker server (local *.test only)")
    received: list[dict] = []

    @app.get("/health")
    def health() -> dict:
        return {"ok": True, "pages": len(_index())}

    @app.get("/site/{host}/{path:path}", response_class=HTMLResponse)
    def site(host: str, path: str, request: Request) -> str:
        return render_url(f"https://{host}/{path}")

    @app.post("/collect")
    async def collect(request: Request) -> JSONResponse:
        """Exfil sink for demos. The benchmark tools never send here (they are sandboxed)."""
        received.append({"body": (await request.body())[:2000].decode("utf-8", "replace")})
        return JSONResponse({"received": len(received)})

    @app.get("/")
    def index() -> dict:
        return {"pages": sorted(_index())}
except ImportError:  # pragma: no cover
    app = None
