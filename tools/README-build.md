# Build Encrypted Profile Artifacts

This project serves an Instagram-style private profile from encrypted files on GitHub Pages.

## Privacy Model

- Raw images and source metadata stay local in `private/` (git-ignored).
- The pattern secret stays local in `.env` (git-ignored).
- Only encrypted files are meant to be committed:
  - `data/manifest.enc.json`
  - `data/media/*.enc.json`

## 1) Prepare Local Private Content

Create local folders/files (do not commit):

- `private/profile-source.json`
- `private/media/` with all referenced images

Expected source schema:

```json
{
  "profile": {
    "username": "your_handle",
    "displayName": "Your Name",
    "bio": "Your bio",
    "avatar": "avatar.jpg"
  },
  "stories": [
    {
      "id": "s1",
      "title": "Travel",
      "media": ["stories/travel-1.jpg", "stories/travel-2.jpg"],
      "caption": "Somewhere nice"
    }
  ],
  "posts": [
    {
      "id": "p1",
      "media": ["posts/post1.jpg", "posts/post2.jpg"],
      "caption": "First post",
      "date": "2026-02-16"
    }
  ]
}
```

All media paths are relative to `private/media/`.
`media` can be either:
- A single string path (single image), or
- An array of string paths (multi-image story/post).

## 2) Set Pattern Secret Locally

Create `.env` (local only):

```bash
PROFILE_PATTERN=1-2-5-8
```

Pattern uses the same dot numbering as lock screen:

```text
1 2 3
4 5 6
7 8 9
```

Use any sequence you want.

## 3) Build Encrypted Artifacts

From repo root:

```bash
python3 tools/build_profile.py
```

Optional flags:

```bash
python3 tools/build_profile.py --source private/profile-source.json --media-root private/media --output data --env-file .env
```

## 4) Publish

Commit encrypted outputs only:

- `profile.html`
- `assets/profile.css`
- `assets/profile.js`
- `data/manifest.enc.json`
- `data/media/*.enc.json`

Do not commit `.env` or `private/`.

## Limitation

This is strong content obfuscation for static hosting, not true server-side access control.
Anyone with the correct pattern can decrypt, and screenshots or manual re-sharing cannot be prevented.

## Optional: Local Instagram-Style Upload Form

If you want a simpler workflow, run:

```bash
python3 tools/local_uploader.py
```

Then open:

```text
http://127.0.0.1:8787
```

On submit, it will:

- Save uploaded images into `private/media/stories/` or `private/media/posts/`
- Name files using ID convention like `s2-1.jpg`, `p3-1.png`
- Append a new story/post entry in `private/profile-source.json`
- Automatically run `python3 tools/build_profile.py`