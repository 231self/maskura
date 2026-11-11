#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Refuse publication unless an existing tag names this source and no release exists."""

import json
import os
import re
import subprocess
from urllib.parse import quote


MAX_TAG_OBJECTS = 8
MAX_RELEASE_PAGES = 20
PAGE_SIZE = 100
MAX_RESPONSE_BYTES = 2**20
SHA = re.compile(r"[0-9a-f]{40}")


class PublicationError(Exception):
    """Messages are fixed categories, never API bodies or upstream exceptions."""


def require(condition, category):
    if not condition:
        raise PublicationError(category)


def gh_get(endpoint):
    """Authenticated GET with explicit HTTP status; gh diagnostics stay private."""
    try:
        result = subprocess.run(
            ["gh", "api", "--hostname", "github.com", "--method", "GET", "--include",
             "--header", "Accept: application/vnd.github+json",
             "--header", "X-GitHub-Api-Version: 2022-11-28", endpoint],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise PublicationError("api-transport-failed") from None
    require(len(result.stdout) <= MAX_RESPONSE_BYTES, "api-response-too-large")
    # gh's included HTTP headers use CRLF or LF, depending on the CLI platform.
    header, separator, body = result.stdout.replace(b"\r\n", b"\n").partition(b"\n\n")
    first = header.split(b"\n", 1)[0]
    match = re.fullmatch(rb"HTTP/[0-9.]+ ([0-9]{3})(?: [^\r\n]*)?", first)
    require(bool(separator) and match is not None, "api-status-invalid")
    status = int(match[1])
    require((status == 200 and result.returncode == 0)
            or (status == 404 and result.returncode == 1), "api-request-failed")
    return status, body


def response(fetch, endpoint):
    try:
        status, body = fetch(endpoint)
        require(type(status) is int and status in (200, 404), "api-request-failed")
        require(isinstance(body, bytes) and len(body) <= MAX_RESPONSE_BYTES,
                "api-response-invalid")

        def unique(items):
            value = {}
            for key, item in items:
                require(key not in value, "api-response-invalid")
                value[key] = item
            return value

        value = json.loads(body, object_pairs_hook=unique)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise PublicationError("api-response-invalid") from None
    if status == 404:
        require(isinstance(value, dict) and value.get("message") == "Not Found",
                "api-response-invalid")
    return status, value


def target(value):
    require(isinstance(value, dict) and value.get("type") in ("commit", "tag")
            and isinstance(value.get("sha"), str) and SHA.fullmatch(value["sha"]),
            "tag-object-invalid")
    return value["type"], value["sha"]


def check_publication(repository, tag, source, fetch=gh_get):
    require(isinstance(repository, str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+", repository),
            "repository-invalid")
    require(isinstance(tag, str) and re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag),
            "release-tag-invalid")
    require(isinstance(source, str) and SHA.fullmatch(source), "source-sha-invalid")
    base = "/repos/" + repository
    status, ref = response(fetch, base + "/git/ref/tags/" + quote(tag, safe=""))
    require(status == 200, "release-tag-missing")
    require(isinstance(ref, dict) and ref.get("ref") == "refs/tags/" + tag,
            "tag-reference-invalid")
    kind, sha = target(ref.get("object"))
    seen = set()
    while kind == "tag":
        require(sha not in seen and len(seen) < MAX_TAG_OBJECTS, "tag-peel-limit")
        seen.add(sha)
        status, annotated = response(fetch, base + "/git/tags/" + sha)
        require(status == 200 and isinstance(annotated, dict)
                and annotated.get("sha") == sha, "tag-object-invalid")
        kind, sha = target(annotated.get("object"))
    require(sha == source, "tag-source-mismatch")

    status, _ = response(fetch, base + "/releases/tags/" + quote(tag, safe=""))
    require(status == 404, "release-already-exists")
    # Do not rely on the by-tag endpoint exposing drafts. An authenticated list
    # includes drafts with the workflow's contents:write token. Exhaust it within
    # a fixed bound; an incomplete scan cannot establish absence.
    for page in range(1, MAX_RELEASE_PAGES + 1):
        status, releases = response(
            fetch, f"{base}/releases?per_page={PAGE_SIZE}&page={page}")
        require(status == 200 and isinstance(releases, list)
                and len(releases) <= PAGE_SIZE, "release-list-invalid")
        for release in releases:
            require(isinstance(release, dict) and isinstance(release.get("tag_name"), str)
                    and bool(release["tag_name"])
                    and type(release.get("draft")) is bool, "release-list-invalid")
            require(release["tag_name"] != tag, "release-already-exists")
        if len(releases) < PAGE_SIZE:
            return
    raise PublicationError("release-list-limit")


def main(environ=None, fetch=gh_get):
    environ = os.environ if environ is None else environ
    try:
        require(bool(environ.get("GH_TOKEN")), "authentication-required")
        check_publication(environ.get("GITHUB_REPOSITORY"), environ.get("RELEASE_TAG"),
                          environ.get("GITHUB_SHA"), fetch)
    except PublicationError as exc:
        print("release publication refused: " + str(exc))
        return 1
    print("release publication guard passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
