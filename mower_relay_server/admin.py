"""Local administrator CLI; never exposed through the public gateway."""

import argparse
import json
import os
import tempfile
from pathlib import Path

from mower_relay_server.registry import Registry


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".relay-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def offline_registry(path):
    registry = Registry(path)
    registry.initialize()
    return registry


def issue(path, subdomain, subject=""):
    return offline_registry(path).issue(subdomain, subject)


def revoke(path, subdomain, subject=None):
    return offline_registry(path).update(subdomain, subject)


def rename(path, old_name, new_name, subject=None):
    return offline_registry(path).update(old_name, subject, new_name)


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
