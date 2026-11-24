#!/usr/bin/env python3
"""Build CLIProxyAPI Store archives and verify the release asset set."""
import argparse
import hashlib
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

ID = "model-fingerprint-guard"
EXTENSIONS = {"darwin": ".dylib", "linux": ".so", "windows": ".dll", "freebsd": ".so"}
PLATFORMS = (
    ("linux", "amd64"), ("linux", "arm64"),
    ("darwin", "amd64"), ("darwin", "arm64"),
    ("windows", "amd64"), ("windows", "arm64"),
    ("freebsd", "amd64"),
)
VERSION_RE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
ROOT = Path(__file__).resolve().parents[1]


def archive_name(version, platform):
    os_name, arch = platform
    return f"{ID}_{version}_{os_name}_{arch}.zip"


def library_name(platform):
    return ID + EXTENSIONS[platform[0]]


def package(version, platform, library, out):
    if not library.is_file() or not library.stat().st_size or library.suffix != EXTENSIONS[platform[0]]:
        raise ValueError(f"Expected a {EXTENSIONS[platform[0]]} dynamic library")
    out.mkdir(parents=True, exist_ok=True)
    archive = out / archive_name(version, platform)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as target:
        entry = zipfile.ZipInfo(library_name(platform))
        entry.create_system = 3
        entry.external_attr = (stat.S_IFREG | 0o755) << 16
        entry.compress_type = zipfile.ZIP_DEFLATED
        target.writestr(entry, library.read_bytes())
        for path in sorted([ROOT / "LICENSE", ROOT / "README.md", ROOT / "config.example.yaml",
                            *ROOT.glob("licenses/*.txt"), *ROOT.glob("docs/*.md"), *ROOT.glob("docs/*.json")]):
            target.write(path, path.relative_to(ROOT).as_posix())
    verify_archive(archive, platform)
    print(archive)


def verify_archive(archive, platform):
    target_name = library_name(platform)
    with zipfile.ZipFile(archive) as handle:
        seen = set()
        libraries = []
        for entry in handle.infolist():
            name = entry.filename
            path = PurePosixPath(name)
            mode = entry.external_attr >> 16
            if (name in seen or "\\" in name or path.is_absolute() or re.match(r"^[A-Za-z]:", name) or ".." in path.parts
                    or (mode and stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR))):
                raise ValueError(f"Invalid ZIP entry in {archive.name}: {name}")
            seen.add(name)
            if path.suffix.lower() in EXTENSIONS.values() and not entry.is_dir():
                libraries.append(name)
                if entry.file_size == 0:
                    raise ValueError(f"Empty dynamic library in {archive.name}")
        if libraries != [target_name]:
            raise ValueError(f"{archive.name} must have exactly one root library named {target_name}")
        if handle.testzip() is not None:
            raise ValueError(f"Corrupt ZIP contents in {archive.name}")


def checksums(version, out, platforms=PLATFORMS):
    required = {archive_name(version, platform): platform for platform in platforms}
    actual = {p.name for p in out.glob("*.zip") if p.is_file()}
    if actual != required.keys():
        raise ValueError(f"Unexpected release assets. Missing: {sorted(required.keys() - actual)}. "
                         f"Extra: {sorted(actual - required.keys())}")
    lines = []
    for name, platform in sorted(required.items()):
        path = out / name
        verify_archive(path, platform)
        with path.open("rb") as binary:
            lines.append(f"{hashlib.file_digest(binary, 'sha256').hexdigest()}  {name}\n")
    (out / "checksums.txt").write_bytes("".join(lines).encode("ascii"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("zip", "checksums"))
    parser.add_argument("--version", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--target")
    parser.add_argument("--library", type=Path)
    args = parser.parse_args()
    if not VERSION_RE.fullmatch(args.version):
        parser.error("version must be a dotted numeric version, for example 0.1.0")
    platform = tuple(args.target.split("-", 1)) if args.target else None
    if platform and platform not in PLATFORMS:
        parser.error("unsupported target")
    if args.command == "zip":
        if not platform or not args.library:
            parser.error("zip requires --target and --library")
        package(args.version, platform, args.library, args.out)
    else:
        checksums(args.version, args.out, (platform,) if platform else PLATFORMS)


if __name__ == "__main__":
    main()
