#!/usr/bin/env python3
"""Build encrypted profile artifacts for GitHub Pages.

Reads local private source and media, encrypts payloads using the pattern secret,
and writes publish-safe encrypted JSON envelopes.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import mimetypes
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

VERSION = 1
ALGORITHM = "AES-CBC+HMAC-SHA256"
PBKDF2_ITERATIONS = 210_000
DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def main() -> int:
    args = parse_args()

    env_values = load_dotenv(args.env_file)
    pattern = os.environ.get("PROFILE_PATTERN") or env_values.get("PROFILE_PATTERN")
    if not pattern:
        fail(
            "PROFILE_PATTERN is missing. Set it in .env or as an environment variable."
        )

    source_path = args.source.resolve()
    media_root = args.media_root.resolve()
    output_root = args.output.resolve()
    output_media_root = output_root / "media"

    if not source_path.exists():
        fail(f"Source file does not exist: {source_path}")
    if not media_root.exists():
        fail(f"Media root does not exist: {media_root}")

    output_root.mkdir(parents=True, exist_ok=True)
    output_media_root.mkdir(parents=True, exist_ok=True)

    source = read_json(source_path)
    validate_source_schema(source)

    media_cache: dict[str, dict[str, Any]] = {}

    def build_media_ref(relative_media_path: str, role_tag: str) -> dict[str, Any]:
        if relative_media_path in media_cache:
            return dict(media_cache[relative_media_path])

        source_file = resolve_media_file(media_root, relative_media_path)
        raw = source_file.read_bytes()
        mime = guess_mime(source_file)
        width, height = image_dimensions(raw)

        digest = hashlib.sha256(raw).hexdigest()[:12]
        stem = sanitize_name(role_tag)
        out_name = f"{stem}-{digest}.enc.json"
        out_path = output_media_root / out_name

        envelope = encrypt_payload(raw, pattern)
        write_json(out_path, envelope)

        ref = {
            "file": to_web_path(out_path),
            "mime": mime,
            "width": width,
            "height": height,
        }
        media_cache[relative_media_path] = ref
        return dict(ref)

    profile = source["profile"]
    manifest_profile = {
        "username": profile["username"],
        "displayName": profile["displayName"],
        "bio": profile["bio"],
        "avatar": build_media_ref(profile["avatar"], "avatar"),
    }

    stories: list[dict[str, Any]] = []
    story_ids: set[str] = set()
    for story in source["stories"]:
        sid = story["id"]
        if sid in story_ids:
            fail(f"Duplicate story id: {sid}")
        story_ids.add(sid)

        stories.append(
            {
                "id": sid,
                "title": story["title"],
                "caption": story["caption"],
                "media": build_media_ref(story["media"], f"story-{sid}"),
            }
        )

    posts: list[dict[str, Any]] = []
    post_ids: set[str] = set()
    for post in source["posts"]:
        pid = post["id"]
        if pid in post_ids:
            fail(f"Duplicate post id: {pid}")
        post_ids.add(pid)

        date = post["date"]
        if not DATE_PATTERN.match(date):
            fail(f"Post '{pid}' has invalid date '{date}'. Expected YYYY-MM-DD")

        posts.append(
            {
                "id": pid,
                "caption": post["caption"],
                "date": date,
                "media": build_media_ref(post["media"], f"post-{pid}"),
            }
        )

    manifest_plain = {
        "version": VERSION,
        "generatedAt": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "profile": manifest_profile,
        "stories": stories,
        "posts": posts,
    }

    manifest_envelope = encrypt_payload(
        json.dumps(manifest_plain, separators=(",", ":"), ensure_ascii=True).encode("utf-8"),
        pattern,
    )
    manifest_out = output_root / "manifest.enc.json"
    write_json(manifest_out, manifest_envelope)

    print("Encrypted profile build complete.")
    print(f"Manifest: {manifest_out}")
    print(f"Media envelopes: {len(media_cache)}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build encrypted profile artifacts.")
    parser.add_argument(
        "--source",
        type=Path,
        default=Path("private/profile-source.json"),
        help="Path to private profile source JSON.",
    )
    parser.add_argument(
        "--media-root",
        type=Path,
        default=Path("private/media"),
        help="Root directory containing private media files.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data"),
        help="Output directory for encrypted artifacts.",
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        default=Path(".env"),
        help="Path to env file containing PROFILE_PATTERN.",
    )
    return parser.parse_args()


def fail(message: str) -> None:
    raise SystemExit(f"[build_profile] {message}")


def read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"Invalid JSON in {path}: {exc}")


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def load_dotenv(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}

    env: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            env[key] = value

    return env


def validate_source_schema(source: dict[str, Any]) -> None:
    required_root = ["profile", "stories", "posts"]
    for key in required_root:
        if key not in source:
            fail(f"Source is missing required key: {key}")

    profile = source["profile"]
    if not isinstance(profile, dict):
        fail("Source 'profile' must be an object")

    for key in ["username", "displayName", "bio", "avatar"]:
        if not isinstance(profile.get(key), str) or not profile[key].strip():
            fail(f"Source profile field '{key}' must be a non-empty string")

    for key in ["stories", "posts"]:
        if not isinstance(source[key], list):
            fail(f"Source '{key}' must be an array")

    for idx, story in enumerate(source["stories"]):
        if not isinstance(story, dict):
            fail(f"Story at index {idx} must be an object")
        for key in ["id", "title", "media", "caption"]:
            if not isinstance(story.get(key), str) or not story[key].strip():
                fail(f"Story index {idx} field '{key}' must be a non-empty string")

    for idx, post in enumerate(source["posts"]):
        if not isinstance(post, dict):
            fail(f"Post at index {idx} must be an object")
        for key in ["id", "media", "caption", "date"]:
            if not isinstance(post.get(key), str) or not post[key].strip():
                fail(f"Post index {idx} field '{key}' must be a non-empty string")


def resolve_media_file(media_root: Path, relative_media_path: str) -> Path:
    rel = Path(relative_media_path)
    if rel.is_absolute() or ".." in rel.parts:
        fail(f"Invalid media path: {relative_media_path}")

    root = media_root.resolve()
    target = (root / rel).resolve()

    if root not in target.parents and target != root:
        fail(f"Media path escapes media root: {relative_media_path}")

    if not target.exists() or not target.is_file():
        fail(f"Missing media file: {target}")

    return target


def sanitize_name(name: str) -> str:
    clean = re.sub(r"[^a-zA-Z0-9_-]+", "-", name).strip("-")
    return clean or "media"


def to_web_path(path: Path) -> str:
    try:
        rel = path.resolve().relative_to(Path.cwd().resolve())
        return rel.as_posix()
    except ValueError:
        return path.as_posix()


def guess_mime(path: Path) -> str:
    guessed, _ = mimetypes.guess_type(path.name)
    return guessed or "application/octet-stream"


def encrypt_payload(plain: bytes, pattern: str) -> dict[str, Any]:
    salt = os.urandom(16)
    iv = os.urandom(16)

    derived = hashlib.pbkdf2_hmac(
        "sha256",
        pattern.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=64,
    )
    enc_key = derived[:32]
    mac_key = derived[32:]

    ciphertext = openssl_encrypt(plain, enc_key, iv)
    mac_message = build_mac_message(VERSION, ALGORITHM, PBKDF2_ITERATIONS, salt, iv, ciphertext)
    mac = hmac.new(mac_key, mac_message, hashlib.sha256).digest()

    return {
        "v": VERSION,
        "alg": ALGORITHM,
        "salt": b64(salt),
        "iv": b64(iv),
        "iter": PBKDF2_ITERATIONS,
        "ciphertext": b64(ciphertext),
        "mac": b64(mac),
    }


def openssl_encrypt(plain: bytes, key: bytes, iv: bytes) -> bytes:
    cmd = [
        "openssl",
        "enc",
        "-aes-256-cbc",
        "-nosalt",
        "-K",
        key.hex(),
        "-iv",
        iv.hex(),
    ]

    try:
        result = subprocess.run(
            cmd,
            input=plain,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError:
        fail("OpenSSL is required but was not found in PATH")

    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        fail(f"OpenSSL encryption failed: {stderr}")

    return result.stdout


def build_mac_message(
    version: int,
    algorithm: str,
    iterations: int,
    salt: bytes,
    iv: bytes,
    ciphertext: bytes,
) -> bytes:
    header = f"v={version};alg={algorithm};iter={iterations};".encode("utf-8")

    return b"".join(
        [
            header,
            len(salt).to_bytes(4, "big"),
            salt,
            len(iv).to_bytes(4, "big"),
            iv,
            len(ciphertext).to_bytes(4, "big"),
            ciphertext,
        ]
    )


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def image_dimensions(payload: bytes) -> tuple[int | None, int | None]:
    if payload.startswith(b"\x89PNG\r\n\x1a\n") and len(payload) >= 24:
        width = int.from_bytes(payload[16:20], "big")
        height = int.from_bytes(payload[20:24], "big")
        return width, height

    if payload.startswith(b"\xff\xd8"):
        return jpeg_dimensions(payload)

    return None, None


def jpeg_dimensions(payload: bytes) -> tuple[int | None, int | None]:
    sof_markers = {
        0xC0,
        0xC1,
        0xC2,
        0xC3,
        0xC5,
        0xC6,
        0xC7,
        0xC9,
        0xCA,
        0xCB,
        0xCD,
        0xCE,
        0xCF,
    }

    idx = 2
    size = len(payload)

    while idx < size:
        if payload[idx] != 0xFF:
            idx += 1
            continue

        while idx < size and payload[idx] == 0xFF:
            idx += 1

        if idx >= size:
            break

        marker = payload[idx]
        idx += 1

        if marker in {0xD8, 0xD9, 0x01} or 0xD0 <= marker <= 0xD7:
            continue

        if idx + 2 > size:
            break

        seg_len = int.from_bytes(payload[idx : idx + 2], "big")
        idx += 2

        if seg_len < 2 or idx + seg_len - 2 > size:
            break

        if marker in sof_markers and seg_len >= 7:
            height = int.from_bytes(payload[idx + 1 : idx + 3], "big")
            width = int.from_bytes(payload[idx + 3 : idx + 5], "big")
            return width, height

        idx += seg_len - 2

    return None, None


if __name__ == "__main__":
    sys.exit(main())
