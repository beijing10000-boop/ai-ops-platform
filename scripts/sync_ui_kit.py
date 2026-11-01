"""Copy the shared ui-kit to the sibling consoles and record its checksums.

The three consoles (AI Ops Platform, SSH MCP Server, Log Analysis Platform)
carry byte-identical copies of ui-kit.css and ui-kit.js. Edit them in one
repository, then run from that repository's root:

    python scripts/sync_ui_kit.py ../ssh-mcp-server ../log-analysis-platform

Every repository gets the same files and the same ui-kit.sha256 manifest,
which tests/test_ui_kit.py checks; commit the change in all three.
"""

import hashlib
import re
import shutil
import sys
from pathlib import Path

FILES = ("ui-kit.css", "ui-kit.js")


def kit_dir(repo):
    """web/assets in the AI Ops Platform, web in the other two consoles."""
    for candidate in (repo / "web" / "assets", repo / "web"):
        if (candidate / FILES[0]).is_file():
            return candidate
    raise SystemExit(f"{repo}: 找不到 ui-kit.css")


def digest(path):
    # Line endings are normalised: a CRLF checkout must not count as an edit.
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def manifest(source):
    match = re.search(r"ui-kit (\d+\.\d+\.\d+)", (source / FILES[0]).read_text("utf-8"))
    if not match:
        raise SystemExit("ui-kit.css 头部缺少版本号（ui-kit x.y.z）")
    lines = [
        f"# ui-kit {match[1]} — identical in the three consoles; see scripts/sync_ui_kit.py"
    ]
    lines += [f"{digest(source / name)}  {name}" for name in FILES]
    return "\n".join(lines) + "\n"


def main(targets):
    source = kit_dir(Path.cwd())
    text = manifest(source)
    (source / "ui-kit.sha256").write_text(text, encoding="utf-8", newline="\n")
    for target in targets:
        destination = kit_dir(Path(target).resolve())
        for name in FILES:
            shutil.copyfile(source / name, destination / name)
        (destination / "ui-kit.sha256").write_text(text, encoding="utf-8", newline="\n")
        print(f"已同步 {destination}")


if __name__ == "__main__":
    main(sys.argv[1:])
