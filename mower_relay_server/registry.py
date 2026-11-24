"""Persistent relay admission records and one-time migration of legacy registries."""

import hashlib
import json
import os
import re
import secrets
import sqlite3
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from mower_relay_server.protocol import valid_subdomain

QUOTA_ZONE = timezone(timedelta(hours=8))


def quota_day():
    return datetime.now(QUOTA_ZONE).date().isoformat()


def daily_usage(row, day):
    if row["traffic_day"] == day:
        return row["traffic_bytes"], row["traffic_state"]
    return 0, "normal"


def install_daily_usage(db):
    db.execute("ALTER TABLE users ADD COLUMN traffic_day TEXT")
    db.execute("ALTER TABLE users ADD COLUMN traffic_bytes INTEGER NOT NULL DEFAULT 0")
    db.execute(
        "ALTER TABLE users ADD COLUMN traffic_state TEXT NOT NULL DEFAULT 'normal'"
    )
    db.execute("PRAGMA user_version=3")


class RegistryConflict(ValueError):
    pass


def unique_keys(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("旧注册文件含重复字段")
        result[key] = value
    return result


class Registry:
    def __init__(self, path):
        path = Path(path).resolve()
        if path.suffix.lower() == ".sqlite3":
            self.path = path
            self.legacy = path.with_suffix(".json")
        else:
            self.legacy = path
            self.path = (
                path.with_suffix(".sqlite3")
                if path.suffix.lower() == ".json"
                else path.with_name(path.name + ".sqlite3")
            )
        self.uri = self.path.as_uri()

    @contextmanager
    def transaction(self, *, write=False):
        mode = "rw" if write else "ro"
        with closing(sqlite3.connect(f"{self.uri}?mode={mode}", uri=True)) as db, db:
            db.row_factory = sqlite3.Row
            db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield db

    def initialize(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        archive = self.legacy.with_name(self.legacy.name + ".migrated")
        with self.transaction(write=True) as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version in (2, 3):
                if self.legacy.exists():
                    raise ValueError("SQLite 已启用，但发现旧注册文件，请核对数据目录")
                if version == 2:
                    install_daily_usage(db)
                return
            if version not in (0, 1):
                raise ValueError("不支持的凭据数据库版本")
            if version == 0:
                if (
                    archive.exists()
                    or db.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone()
                ):
                    raise ValueError("无法初始化凭据数据库，请检查或恢复已有数据库")
                db.execute("""CREATE TABLE users (
                    subdomain TEXT PRIMARY KEY NOT NULL,
                    subject TEXT NOT NULL,
                    enabled INTEGER NOT NULL CHECK (enabled IN (0,1)),
                    credential_sha256 TEXT NOT NULL)""")
                db.execute(
                    "CREATE UNIQUE INDEX active_subject ON users(subject) WHERE enabled=1 AND subject<>''"
                )
                db.execute(
                    "CREATE UNIQUE INDEX active_digest ON users(credential_sha256) WHERE enabled=1"
                )
                if not self.legacy.exists():
                    install_daily_usage(db)
                    return
                self._import(db)
                db.execute("PRAGMA user_version=1")
        # Version 1 has committed every row. Finish archiving before serving requests.
        with self.transaction(write=True) as db:
            if db.execute("PRAGMA user_version").fetchone()[0] == 1:
                if self.legacy.exists() == archive.exists():
                    raise ValueError("凭据已导入，请核对旧注册文件及迁移备份")
                if self.legacy.exists():
                    self.legacy.rename(archive)
                install_daily_usage(db)

    def _import(self, db):
        users = json.loads(
            self.legacy.read_text("utf-8-sig"), object_pairs_hook=unique_keys
        )
        if not isinstance(users, dict):
            raise ValueError("旧注册文件格式无效")
        for name, row in users.items():
            if not valid_subdomain(name) or not isinstance(row, dict):
                raise ValueError("旧注册文件含无效用户记录")
            subject = row.get("subject", "")
            enabled = row.get("enabled")
            digest = row.get("credential_sha256")
            if (
                type(enabled) is not bool
                or not isinstance(subject, str)
                or not isinstance(digest, str)
                or not re.fullmatch("[0-9a-f]{64}", digest)
            ):
                raise ValueError(f"旧注册文件记录格式无效：{name}")
            db.execute(
                "INSERT INTO users VALUES (?,?,?,?)", (name, subject, enabled, digest)
            )

    def get(self, name):
        with self.transaction() as db:
            return db.execute(
                "SELECT * FROM users WHERE subdomain=?", (name,)
            ).fetchone()

    def identify(self, digest):
        with self.transaction() as db:
            row = db.execute(
                "SELECT subdomain FROM users WHERE credential_sha256=? AND enabled=1",
                (digest,),
            ).fetchone()
            return row[0] if row else None

    def charge_traffic(self, name, digest, size, limit):
        """Reserve a whole message before forwarding it; serialize charges across peers."""
        with self.transaction(write=True) as db:
            day = quota_day()
            row = db.execute(
                "SELECT traffic_day,traffic_bytes,traffic_state FROM users "
                "WHERE subdomain=? AND credential_sha256=? AND enabled=1",
                (name, digest),
            ).fetchone()
            if row is None:
                raise RegistryConflict("中转凭据已失效")
            used, previous = daily_usage(row, day)
            if previous == "limited":
                return False, None, used, day
            allowed = used + size <= limit
            if allowed:
                used += size
            state = previous
            if not allowed or used == limit:
                state = "limited"
            elif used * 5 >= limit * 4:
                state = "warning"
            db.execute(
                "UPDATE users SET traffic_day=?,traffic_bytes=?,traffic_state=? WHERE subdomain=?",
                (day, used, state, name),
            )
            return allowed, state if state != previous else None, used, day

    def page(self, subject, offset, limit):
        where, args = ("", ()) if subject is None else (" WHERE subject=?", (subject,))
        with self.transaction() as db:
            total = db.execute("SELECT count(*) FROM users" + where, args).fetchone()[0]
            rows = db.execute(
                "SELECT subdomain,subject,enabled,traffic_day,traffic_bytes,traffic_state FROM users"
                + where
                + " ORDER BY subdomain LIMIT ? OFFSET ?",
                (*args, limit, min(offset, total)),
            ).fetchall()
        return total, rows

    def issue(self, name, subject=""):
        if not valid_subdomain(name):
            raise ValueError("子域名格式无效")
        credential = secrets.token_urlsafe(48)
        digest = hashlib.sha256(credential.encode()).hexdigest()
        with self.transaction(write=True) as db:
            db.execute("DELETE FROM users WHERE subdomain=? AND enabled=0", (name,))
            try:
                db.execute(
                    "INSERT INTO users(subdomain,subject,enabled,credential_sha256) VALUES (?,?,1,?)",
                    (name, subject, digest),
                )
            except sqlite3.IntegrityError:
                raise RegistryConflict("子域名或用户已启用") from None
        return credential

    def update(self, name, subject, target=None):
        if target is not None and not valid_subdomain(target):
            raise ValueError("子域名格式无效")
        with self.transaction(write=True) as db:
            row = db.execute(
                "SELECT * FROM users WHERE subdomain=?", (name,)
            ).fetchone()
            if row is None:
                raise KeyError(name)
            if subject is not None and row["subject"] != subject:
                raise RegistryConflict("子域名已不属于该用户")
            if target is None:
                db.execute("UPDATE users SET enabled=0 WHERE subdomain=?", (name,))
            elif not row["enabled"]:
                raise RegistryConflict("该凭据已吊销")
            elif name != target:
                db.execute(
                    "DELETE FROM users WHERE subdomain=? AND enabled=0", (target,)
                )
                try:
                    db.execute(
                        "UPDATE users SET subdomain=? WHERE subdomain=?", (target, name)
                    )
                except sqlite3.IntegrityError:
                    raise RegistryConflict("新子域名已被占用") from None
            return {
                "subject": row["subject"],
                "enabled": target is not None,
                "credential_sha256": row["credential_sha256"],
                "traffic_day": row["traffic_day"],
                "traffic_bytes": row["traffic_bytes"],
                "traffic_state": row["traffic_state"],
            }
