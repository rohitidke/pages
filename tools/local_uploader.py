#!/usr/bin/env python3
"""Local upload form for profile content.

Runs a localhost web form that:
- Accepts post/story image uploads
- Captures caption (+ title/date where needed)
- Saves files to private/media/{stories|posts} with id-based naming
- Updates private/profile-source.json
- Triggers python3 tools/build_profile.py
"""

from __future__ import annotations

import argparse
import cgi
import datetime as dt
import html
import json
import re
import shutil
import subprocess
import traceback
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

ID_PATTERN = re.compile(r"^[sp](\d+)$")
DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def main() -> int:
    args = parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    source_path = repo_root / "private" / "profile-source.json"
    media_root = repo_root / "private" / "media"

    if not source_path.exists():
        raise SystemExit(f"Missing source file: {source_path}")

    (media_root / "stories").mkdir(parents=True, exist_ok=True)
    (media_root / "posts").mkdir(parents=True, exist_ok=True)

    handler = build_handler(repo_root, source_path, media_root)
    server = ThreadingHTTPServer((args.host, args.port), handler)

    print(f"Local uploader running at http://{args.host}:{args.port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping uploader.")
    finally:
        server.server_close()

    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run local profile upload form.")
    parser.add_argument("--host", default="127.0.0.1", help="Host address. Default: 127.0.0.1")
    parser.add_argument("--port", type=int, default=8787, help="Port. Default: 8787")
    return parser.parse_args()


def build_handler(repo_root: Path, source_path: Path, media_root: Path):
    class UploadHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path not in {"/", "/index.html"}:
                self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
                return

            query = parse_qs(parsed.query)
            message = query.get("msg", [""])[0]
            is_error = query.get("err", ["0"])[0] == "1"
            self.respond_html(render_form_page(message=message, is_error=is_error))

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path != "/upload":
                self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
                return

            try:
                result = handle_upload(
                    source_path=source_path,
                    media_root=media_root,
                    headers=self.headers,
                    rfile=self.rfile,
                    repo_root=repo_root,
                )
            except Exception as exc:  # noqa: BLE001
                tb = traceback.format_exc(limit=4)
                msg = f"Upload failed: {exc}\n{tb}"
                self.respond_html(render_form_page(message=msg, is_error=True), HTTPStatus.BAD_REQUEST)
                return

            self.respond_html(render_success_page(result))

        def log_message(self, fmt: str, *args: object) -> None:
            return

        def respond_html(self, body: str, status: HTTPStatus = HTTPStatus.OK) -> None:
            payload = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    return UploadHandler


def handle_upload(
    source_path: Path,
    media_root: Path,
    headers: Any,
    rfile: Any,
    repo_root: Path,
) -> dict[str, Any]:
    content_type = headers.get("Content-Type", "")
    if "multipart/form-data" not in content_type:
        raise ValueError("Expected multipart form upload")

    form = cgi.FieldStorage(
        fp=rfile,
        headers=headers,
        environ={
            "REQUEST_METHOD": "POST",
            "CONTENT_TYPE": content_type,
        },
    )

    item_type = (form.getfirst("item_type") or "").strip()
    if item_type not in {"post", "story"}:
        raise ValueError("Item type must be post or story")

    caption = (form.getfirst("caption") or "").strip()
    if not caption:
        raise ValueError("Caption is required")

    title = (form.getfirst("title") or "").strip()
    date = (form.getfirst("date") or "").strip()
    if item_type == "story" and not title:
        raise ValueError("Story title is required")
    if item_type == "post":
        if not date:
            date = dt.date.today().isoformat()
        if not DATE_PATTERN.match(date):
            raise ValueError("Post date must be YYYY-MM-DD")

    if "images" not in form:
        raise ValueError("Select at least one image file")

    files_field = form["images"]
    raw_items = files_field if isinstance(files_field, list) else [files_field]
    file_items = []
    for item in raw_items:
        if not isinstance(item, cgi.FieldStorage):
            continue
        filename = getattr(item, "filename", None)
        if isinstance(filename, str) and filename.strip():
            file_items.append(item)

    if not file_items:
        raise ValueError("No valid files uploaded")

    source = json.loads(source_path.read_text(encoding="utf-8"))
    if "stories" not in source or "posts" not in source:
        raise ValueError("profile-source.json is missing stories/posts arrays")

    collection_key = "posts" if item_type == "post" else "stories"
    prefix = "p" if item_type == "post" else "s"
    next_id = allocate_next_id(source[collection_key], prefix)

    folder = "posts" if item_type == "post" else "stories"
    target_dir = media_root / folder
    target_dir.mkdir(parents=True, exist_ok=True)

    media_paths: list[str] = []
    for idx, item in enumerate(file_items, start=1):
        ext = normalize_ext(item.filename)
        filename = f"{next_id}-{idx}{ext}"
        target_path = target_dir / filename
        with target_path.open("wb") as out_file:
            shutil.copyfileobj(item.file, out_file)
        media_paths.append(f"{folder}/{filename}")

    entry: dict[str, Any] = {
        "id": next_id,
        "media": media_paths,
        "caption": caption,
    }

    if item_type == "post":
        entry["date"] = date
    else:
        entry["title"] = title

    source[collection_key].append(entry)
    source_path.write_text(json.dumps(source, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

    build_cmd = ["python3", "tools/build_profile.py"]
    build = subprocess.run(
        build_cmd,
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if build.returncode != 0:
        raise ValueError(
            "Build failed after upload.\n\n"
            f"Command: {' '.join(build_cmd)}\n\n"
            f"{build.stdout}\n{build.stderr}".strip()
        )

    return {
        "item_type": item_type,
        "id": next_id,
        "files": media_paths,
        "build_output": (build.stdout + "\n" + build.stderr).strip(),
    }


def allocate_next_id(items: list[dict[str, Any]], prefix: str) -> str:
    max_num = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        raw_id = str(item.get("id", "")).strip()
        match = ID_PATTERN.match(raw_id)
        if not match:
            continue
        if not raw_id.startswith(prefix):
            continue
        max_num = max(max_num, int(match.group(1)))
    return f"{prefix}{max_num + 1}"


def normalize_ext(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    if ext in {".jpg", ".jpeg", ".png", ".webp", ".gif", ".svg"}:
        return ext
    return ".jpg"


def render_form_page(message: str = "", is_error: bool = False) -> str:
    safe_message = html.escape(message)
    message_html = ""
    if safe_message:
        cls = "msg msg-error" if is_error else "msg msg-ok"
        message_html = f"<pre class='{cls}'>{safe_message}</pre>"

    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Local Profile Uploader</title>
    <style>
      :root {{
        --bg: #0f172a;
        --bg2: #1e293b;
        --card: #ffffff;
        --ink: #0f172a;
        --muted: #64748b;
        --line: #cbd5e1;
        --accent: #f97316;
        --accent2: #ec4899;
        --good: #065f46;
        --bad: #991b1b;
      }}
      * {{ box-sizing: border-box; }}
      body {{
        margin: 0;
        font-family: "Space Grotesk", "Segoe UI", sans-serif;
        background: radial-gradient(1200px 640px at 8% 0%, #1d4ed8 0%, transparent 45%),
          radial-gradient(1000px 700px at 88% 10%, #9d174d 0%, transparent 42%),
          linear-gradient(130deg, var(--bg), var(--bg2));
        min-height: 100vh;
        color: var(--ink);
        display: grid;
        place-items: center;
        padding: 18px;
      }}
      .card {{
        width: min(780px, 100%);
        background: var(--card);
        border-radius: 26px;
        box-shadow: 0 24px 70px rgba(2, 6, 23, 0.45);
        padding: 20px;
        border: 1px solid rgba(255, 255, 255, 0.4);
      }}
      h1 {{ margin: 0; font-size: clamp(1.5rem, 3vw, 2rem); }}
      .sub {{ margin: 8px 0 18px; color: var(--muted); }}
      .grid {{
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 12px;
      }}
      .field {{ display: grid; gap: 6px; }}
      label {{ font-weight: 600; }}
      input, select, textarea {{
        width: 100%;
        border: 1px solid var(--line);
        border-radius: 12px;
        padding: 10px 12px;
        font: inherit;
      }}
      textarea {{ min-height: 96px; resize: vertical; }}
      .full {{ grid-column: 1 / -1; }}
      .hint {{ color: var(--muted); font-size: 0.86rem; margin-top: 4px; }}
      .btn {{
        margin-top: 14px;
        border: 0;
        border-radius: 999px;
        background: linear-gradient(135deg, var(--accent), var(--accent2));
        color: #fff;
        font-weight: 700;
        padding: 12px 20px;
        cursor: pointer;
      }}
      .msg {{
        white-space: pre-wrap;
        overflow-wrap: anywhere;
        border-radius: 12px;
        padding: 10px 12px;
        margin: 0 0 12px;
        border: 1px solid;
        font-size: 0.86rem;
      }}
      .msg-ok {{ color: var(--good); border-color: #6ee7b7; background: #ecfdf5; }}
      .msg-error {{ color: var(--bad); border-color: #fca5a5; background: #fef2f2; }}
      @media (max-width: 640px) {{
        .grid {{ grid-template-columns: 1fr; }}
      }}
    </style>
  </head>
  <body>
    <main class="card">
      <h1>Local Uploader</h1>
      <p class="sub">Upload images, write caption, and auto-publish encrypted artifacts.</p>
      {message_html}
      <form action="/upload" method="post" enctype="multipart/form-data">
        <div class="grid">
          <div class="field">
            <label for="item_type">Type</label>
            <select id="item_type" name="item_type" required>
              <option value="post">Post</option>
              <option value="story">Story</option>
            </select>
          </div>
          <div class="field">
            <label for="date">Date (posts only)</label>
            <input id="date" name="date" type="date" value="{dt.date.today().isoformat()}" />
          </div>
          <div class="field full">
            <label for="title">Title (stories only)</label>
            <input id="title" name="title" placeholder="Trip / Gym / Work / etc." />
          </div>
          <div class="field full">
            <label for="caption">Caption</label>
            <textarea id="caption" name="caption" placeholder="Write your caption..." required></textarea>
          </div>
          <div class="field full">
            <label for="images">Images</label>
            <input id="images" name="images" type="file" accept="image/*,.svg" multiple required />
            <p class="hint">
              Files are saved as <code>sN-1.ext</code> or <code>pN-1.ext</code>, profile-source is updated,
              then <code>python3 tools/build_profile.py</code> runs automatically.
            </p>
          </div>
        </div>
        <button class="btn" type="submit">Upload & Build</button>
      </form>
    </main>
    <script>
      const typeSelect = document.getElementById("item_type");
      const dateInput = document.getElementById("date");
      const titleInput = document.getElementById("title");
      function syncVisibility() {{
        const isStory = typeSelect.value === "story";
        titleInput.required = isStory;
        dateInput.required = !isStory;
      }}
      typeSelect.addEventListener("change", syncVisibility);
      syncVisibility();
    </script>
  </body>
</html>"""


def render_success_page(result: dict[str, Any]) -> str:
    file_list = "\n".join(f"- {path}" for path in result["files"])
    build_output = html.escape(result["build_output"])
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Upload Complete</title>
    <style>
      body {{
        margin: 0;
        font-family: "Space Grotesk", "Segoe UI", sans-serif;
        background: #020617;
        color: #e2e8f0;
        padding: 20px;
      }}
      .card {{
        max-width: 860px;
        margin: 0 auto;
        border: 1px solid #334155;
        border-radius: 16px;
        padding: 16px;
        background: #0f172a;
      }}
      h1 {{ margin-top: 0; }}
      pre {{
        white-space: pre-wrap;
        overflow-wrap: anywhere;
        background: #111827;
        border-radius: 10px;
        padding: 12px;
        border: 1px solid #334155;
      }}
      a {{
        display: inline-block;
        margin-top: 12px;
        color: #93c5fd;
      }}
    </style>
  </head>
  <body>
    <main class="card">
      <h1>Upload Complete</h1>
      <p>Created <strong>{html.escape(result["item_type"])}</strong> with id <strong>{html.escape(result["id"])}</strong>.</p>
      <pre>{html.escape(file_list)}</pre>
      <p>Build output:</p>
      <pre>{build_output}</pre>
      <a href="/">Upload another</a>
    </main>
  </body>
</html>"""


if __name__ == "__main__":
    raise SystemExit(main())
