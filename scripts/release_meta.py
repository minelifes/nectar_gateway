#!/usr/bin/env python3
"""Release metadata for Nectar components (same file in nectar_apps and nectar_gateway).

  release_meta.py release-json --component panel --version 1.4.2 --image ghcr.io/minelifes/nectar-apps@sha256:… \
      --api-version-file internal/version/version.go --migrations-glob 'internal/store/migrations/*' > release.json
  release_meta.py update-feed --feed updates.json --release release.json
  release_meta.py next-version [--bump auto|major|minor|patch]   # version of a "release"-labelled merge
  release_meta.py tag-ahead                                      # "true" when a tag is newer than the manifest

release.json describes one release (read by the panel's updater):
  component, version, channel (stable | beta), image (pinned digest), kind (patch | minor | major),
  security, breaking, api_version, requires, migrations, notes, published_at

Conventions (conventional commits since the previous tag):
  feat!: … / BREAKING CHANGE  → breaking (never auto-installed)
  fix(security): … / security: … / [security] → security fix (allowed by "patch only" auto-update)
"""
import argparse
import datetime
import fnmatch
import glob
import json
import os
import re
import subprocess
import sys

SEMVER = re.compile(r"^(?:[A-Za-z0-9_.-]+-)?v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$")


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout.strip()


def parse(v):
    m = SEMVER.match(v)
    if not m:
        sys.exit(f"not a semantic version: {v}")
    return int(m[1]), int(m[2]), int(m[3]), m[4] or ""


def previous_tag(version):
    tags = [t for t in git("tag", "--list").split() if SEMVER.match(t)]
    cur = parse(version)
    older = sorted((parse(t)[:3], t) for t in tags if parse(t)[:3] < cur[:3] and not parse(t)[3])
    return older[-1][1] if older else None


def kind(prev, cur):
    if prev is None:
        return "major" if cur[0] > 0 else "minor"
    if cur[0] != prev[0]:
        return "major"
    if cur[1] != prev[1]:
        return "minor"
    return "patch"


def release_json(a):
    cur = parse(a.version)
    prev = previous_tag(a.version)
    rng = f"{prev}..HEAD" if prev else "HEAD"
    log = git("log", "--format=%s%n%b%n--end--", rng)
    subjects = [s for s in git("log", "--format=%s", rng).splitlines() if s]
    breaking = bool(re.search(r"^\w+(\(.+\))?!:|BREAKING CHANGE", log, re.M))
    security = bool(re.search(r"^(fix|security)(\(security\))?:|^fix\(security\):|\[security\]", log, re.M | re.I))
    migrations = False
    if a.migrations_glob:
        changed = git("diff", "--name-only", prev, "HEAD").splitlines() if prev else glob.glob(a.migrations_glob)
        migrations = any(fnmatch.fnmatch(f, a.migrations_glob) for f in changed)
    api_version = None
    if a.api_version_file and os.path.exists(a.api_version_file):
        m = re.search(r"APIVersion\s*=\s*(\d+)", open(a.api_version_file).read())
        api_version = int(m[1]) if m else None
    requires = {}
    if a.requires and os.path.exists(a.requires):
        requires = json.load(open(a.requires))
    notes = [s for s in subjects if not s.startswith(("chore", "ci", "test", "docs", "Merge"))][:50]
    out = {
        "component": a.component,
        "version": f"{cur[0]}.{cur[1]}.{cur[2]}" + (f"-{cur[3]}" if cur[3] else ""),
        "channel": "beta" if cur[3] else "stable",
        "image": a.image,
        "kind": kind(parse(prev) if prev else None, cur),
        "security": security,
        "breaking": breaking or (prev is not None and cur[0] > parse(prev)[0] and cur[0] > 0),
        "api_version": api_version,
        "requires": requires,
        "migrations": migrations,
        "notes": "\n".join(f"- {s}" for s in notes),
        "previous": prev.lstrip("v") if prev else None,
        "published_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    }
    json.dump(out, sys.stdout, indent=2)
    print()


def update_feed(a):
    rel = json.load(open(a.release))
    feed = {"schema": 1, "components": {}}
    if os.path.exists(a.feed):
        feed = json.load(open(a.feed))
    comp = feed.setdefault("components", {}).setdefault(rel["component"], {})
    for channel in ("stable", "beta") if rel["channel"] == "stable" else ("beta",):
        lst = [r for r in comp.get(channel, []) if r["version"] != rel["version"]]
        lst.insert(0, rel)
        lst.sort(key=lambda r: parse(r["version"])[:3] + ((1,) if not parse(r["version"])[3] else (0,)), reverse=True)
        comp[channel] = lst[: a.keep]
    feed["updated_at"] = rel["published_at"]
    json.dump(feed, open(a.feed, "w"), indent=2)
    print(f"{a.feed}: {rel['component']} {rel['version']} ({rel['channel']})")


def manifest_version(path=".release-please-manifest.json"):
    try:
        with open(path) as f:
            return json.load(f).get(".", "0.0.0")
    except FileNotFoundError:
        return "0.0.0"


def latest_stable_tag():
    tags = [t for t in git("tag", "--list").split() if SEMVER.match(t) and not parse(t)[3]]
    return max(tags, key=lambda t: parse(t)[:3]) if tags else None


def next_version(a):
    """The next version for a merged pull request labelled "release": the newer of the latest stable tag and
    the release-please manifest, bumped like release-please would (feat → minor, fix and others → patch,
    feat! / BREAKING CHANGE → major; before 1.0 a breaking change bumps the minor version), or as the label
    release:major|minor|patch says."""
    tag = latest_stable_tag()
    base = max([parse(manifest_version(a.manifest))[:3]] + ([parse(tag)[:3]] if tag else []))
    bump = a.bump
    if bump == "auto":
        log = git("log", "--format=%s%n%b%x1e", f"{tag}..HEAD" if tag else "HEAD")
        commits = [c.strip() for c in log.split("\x1e") if c.strip()]
        if not commits:
            sys.exit(f"nothing to release: no commits since {tag}")
        subjects = [c.splitlines()[0] for c in commits]
        if any(re.match(r"^\w+(\([^)]*\))?!:", s) for s in subjects) or any("BREAKING CHANGE" in c for c in commits):
            bump = "minor" if base[0] == 0 else "major"
        elif any(re.match(r"^feat(\([^)]*\))?:", s) for s in subjects):
            bump = "minor"
        else:
            bump = "patch"
    major, minor, patch = base
    if bump == "major":
        major, minor, patch = major + 1, 0, 0
    elif bump == "minor":
        minor, patch = minor + 1, 0
    else:
        patch += 1
    print(f"{major}.{minor}.{patch}")


def tag_ahead(a):
    """true when the latest stable tag is newer than the release-please manifest (a labelled release
    happened since the last release PR): release-please would propose a version that already exists."""
    tag = latest_stable_tag()
    print("true" if tag and parse(tag)[:3] > parse(manifest_version(a.manifest))[:3] else "false")


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("release-json")
    r.add_argument("--component", required=True)
    r.add_argument("--version", required=True)
    r.add_argument("--image", required=True)
    r.add_argument("--api-version-file")
    r.add_argument("--migrations-glob")
    r.add_argument("--requires", default=".github/release-requires.json")
    f = sub.add_parser("update-feed")
    f.add_argument("--feed", required=True)
    f.add_argument("--release", required=True)
    f.add_argument("--keep", type=int, default=30)
    n = sub.add_parser("next-version")
    n.add_argument("--bump", default="auto", choices=["auto", "major", "minor", "patch"])
    n.add_argument("--manifest", default=".release-please-manifest.json")
    t = sub.add_parser("tag-ahead")
    t.add_argument("--manifest", default=".release-please-manifest.json")
    a = p.parse_args()
    {"release-json": release_json, "update-feed": update_feed, "next-version": next_version, "tag-ahead": tag_ahead}[a.cmd](a)


if __name__ == "__main__":
    main()
