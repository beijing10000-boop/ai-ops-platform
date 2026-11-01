"""The shared ui-kit is the same version and the same bytes in every console."""

import hashlib
import re
from pathlib import Path

KIT = Path(__file__).resolve().parent.parent / "web" / "assets"


def digest(path):
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def test_ui_kit_matches_its_manifest():
    """Edit ui-kit in one repository, then run scripts/sync_ui_kit.py: it copies
    the files to the other consoles and rewrites this manifest in all three."""
    lines = (KIT / "ui-kit.sha256").read_text(encoding="utf-8").splitlines()
    recorded = dict(reversed(line.split("  ")) for line in lines[1:] if line)
    assert recorded == {
        name: digest(KIT / name) for name in ("ui-kit.css", "ui-kit.js")
    }


def test_ui_kit_version_is_one_number():
    css = re.search(r"ui-kit (\d+\.\d+\.\d+)", (KIT / "ui-kit.css").read_text("utf-8"))
    js = re.search(
        r'VERSION = "(\d+\.\d+\.\d+)"', (KIT / "ui-kit.js").read_text("utf-8")
    )
    manifest = re.search(
        r"ui-kit (\d+\.\d+\.\d+)", (KIT / "ui-kit.sha256").read_text("utf-8")
    )
    assert css and js and manifest
    assert css[1] == js[1] == manifest[1]
