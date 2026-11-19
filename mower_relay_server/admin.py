"""Local administrator CLI; never exposed through the public gateway."""

import argparse
import hashlib
import json
import os
import secrets
import tempfile
from contextlib import contextmanager
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


@contextmanager
def registry_lock(path):
    # users.json is atomically replaced. Lock a stable sibling across processes.
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.with_name(path.name + ".lock").open("a+b") as lock:
        if os.name == "nt":
            import msvcrt

            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(lock, fcntl.LOCK_EX)
        yield  # Closing the descriptor releases the lock on both platforms.


def initialize_registry(path):
    with registry_lock(path):
        if not path.exists():
            write_json(path, {})


class RegistryConflict(ValueError):
    pass


def issue(path, subdomain, subject=""):
    if not valid_subdomain(subdomain):
        raise ValueError("子域名格式无效")
    with registry_lock(path):
        users = json.loads(path.read_text("utf-8")) if path.exists() else {}
        if subdomain in users and users[subdomain].get("enabled"):
            raise RegistryConflict("该子域名已启用；请先吊销原凭据")
        if subject and any(
            record.get("enabled") and record.get("subject") == subject
            for record in users.values()
            if isinstance(record, dict)
        ):
            raise RegistryConflict("该用户已有启用的子域名")
        credential = secrets.token_urlsafe(48)
        users[subdomain] = {
            "enabled": True,
            "subject": subject,
            "credential_sha256": hashlib.sha256(credential.encode()).hexdigest(),
        }
        write_json(path, users)
    return credential


def rename(path, old_name, new_name, subject=None):
    if not valid_subdomain(old_name) or not valid_subdomain(new_name):
        raise ValueError("子域名格式无效")
    with registry_lock(path):
        users = json.loads(path.read_text("utf-8"))
        record = users[old_name]
        if subject is not None and record.get("subject", "") != subject:
            raise RegistryConflict("原子域名已不属于该用户")
        if not record.get("enabled"):
            raise RegistryConflict("该凭据已吊销")
        if new_name != old_name:
            if users.get(new_name, {}).get("enabled"):
                raise RegistryConflict("新子域名已被占用")
            users[new_name] = users.pop(old_name)
            write_json(path, users)
        return record


def revoke(path, subdomain, subject=None):
    with registry_lock(path):
        users = json.loads(path.read_text("utf-8"))
        record = users[subdomain]
        if subject is not None and record.get("subject", "") != subject:
            raise RegistryConflict("子域名已不属于该用户")
        record["enabled"] = False
        write_json(path, users)
        return record


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
