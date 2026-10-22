"""Local administrator CLI; never exposed through the public gateway."""

import argparse
import hashlib
import json
import os
import secrets
import tempfile
from pathlib import Path

from mower_relay_server.protocol import valid_subdomain


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".relay-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def issue(path, subdomain, subject=""):
    if not valid_subdomain(subdomain):
        raise ValueError("子域名格式无效")
    users = json.loads(path.read_text("utf-8")) if path.exists() else {}
    if subdomain in users and users[subdomain].get("enabled"):
        raise ValueError("该子域名已启用；请先吊销原凭据")
    credential = secrets.token_urlsafe(48)
    users[subdomain] = {
        "enabled": True,
        "subject": subject,
        "credential_sha256": hashlib.sha256(credential.encode()).hexdigest(),
    }
    write_json(path, users)
    return credential


def revoke(path, subdomain):
    users = json.loads(path.read_text("utf-8"))
    users[subdomain]["enabled"] = False
    write_json(path, users)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", required=True, type=Path)
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("issue", "revoke"):
        sub.add_parser(action).add_argument("subdomain")
    args = parser.parse_args()
    if args.action == "issue":
        # The raw credential is returned once for delivery to the reviewed user.
        print(issue(args.registry, args.subdomain))
    else:
        revoke(args.registry, args.subdomain)


if __name__ == "__main__":
    main()
