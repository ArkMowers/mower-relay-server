"""Serve administrator-published frontend builds, shared by connected instances."""

import asyncio
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import time
from pathlib import Path, PurePosixPath, PureWindowsPath
from zipfile import ZipFile

import aiohttp

BUILD = re.compile(r"[0-9a-f]{64}")
ARCHIVE_LIMIT = 32 * 1024 * 1024
BUILD_LIMIT = 64 * 1024 * 1024
CACHE_LIMIT = 256 * 1024 * 1024
MIN_DOWNLOAD_RATE = 8 * 1024  # Bytes per second for a slow GitHub connection.
RELEASE_API = "https://api.github.com/repos"
PUBLISHERS = ("ArkMowers/arknights-mower", "ArkMowers/mower-relay-server")


def asset_download_timeout(size):
    if type(size) is not int or not 0 < size <= ARCHIVE_LIMIT:
        raise ValueError("前端压缩包大小无效或超过下载上限")
    return aiohttp.ClientTimeout(
        total=120 + size / MIN_DOWNLOAD_RATE, sock_connect=12, sock_read=60
    )


def unpack(archive, destination, build):
    with ZipFile(archive) as bundle:
        entries = bundle.infolist()
        if len(entries) > 8192 or sum(item.file_size for item in entries) > BUILD_LIMIT:
            raise ValueError("前端文件超过缓存限制")
        for item in entries:
            path = PurePosixPath(item.filename)
            if (
                not path.parts
                or path.is_absolute()
                or ".." in path.parts
                or "\\" in item.filename
                or ":" in item.filename
                or stat.S_ISLNK(item.external_attr >> 16)
                or any(
                    part.rstrip(". ") != part or PureWindowsPath(part).is_reserved()
                    for part in path.parts
                )
            ):
                raise ValueError("前端包路径无效")
            target = destination.joinpath(*path.parts)
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(item) as src, target.open("xb") as dst:
                    shutil.copyfileobj(src, dst, 65536)
    if json.loads((destination / "relay-ui.json").read_bytes()).get("build") != build:
        raise ValueError("前端构建标识不匹配")
    pages = json.loads((destination / "frontend-routes.json").read_bytes())
    if (
        not isinstance(pages, list)
        or "/" not in pages
        or not all(isinstance(p, str) for p in pages)
    ):
        raise ValueError("前端路由清单无效")
    if not (destination / "index.html").is_file():
        raise ValueError("前端包缺少首页")


class UiCache:
    def __init__(self, root, pinned):
        self.root = Path(root)
        self.pinned = pinned
        self.jobs = {}
        self.states = {}
        self.lock = asyncio.Lock()
        self.capacity = CACHE_LIMIT

    def directory(self, build):
        if not isinstance(build, str) or not BUILD.fullmatch(build):
            raise ValueError("前端构建标识无效")
        return self.root / build

    def state(self, build, retry=False):
        folder = self.directory(build)
        if folder.is_dir():
            if time.time() - folder.stat().st_mtime > 60:
                os.utime(folder)
            return {"phase": "ready"}
        if build not in self.jobs and (retry or build not in self.states):
            if len(self.jobs) >= 16:
                return {"phase": "error", "message": "等待下载的版本较多，请稍后重试"}
            self.states[build] = {"phase": "waiting"}
            self.jobs[build] = asyncio.create_task(self.install(build))
        return self.states[build]

    def reserve(self):
        self.root.mkdir(parents=True, exist_ok=True)
        used = 0
        entries = []
        for path in self.root.iterdir():
            if path.is_dir() and BUILD.fullmatch(path.name):
                size = sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
                used += size
                entries.append((path.stat().st_mtime, path, size))
            elif path.is_dir() and path.name.startswith(".incoming-"):
                shutil.rmtree(path)
        reserve = ARCHIVE_LIMIT + BUILD_LIMIT
        for _, path, size in sorted(entries):
            if used + reserve <= self.capacity:
                break
            if path.name not in self.pinned():
                shutil.rmtree(path)
                used -= size
        if used + reserve > self.capacity:
            raise ValueError("缓存空间已被在线实例占用")

    async def download(self, build, archive):
        timeout = aiohttp.ClientTimeout(total=240, sock_connect=12, sock_read=40)
        async with aiohttp.ClientSession(timeout=timeout, trust_env=True) as session:
            for repo in PUBLISHERS:
                base = f"{RELEASE_API}/{repo}/releases"
                async with session.get(f"{base}/tags/relay-ui") as metadata:
                    if metadata.status == 404:
                        continue
                    metadata.raise_for_status()
                    release = await metadata.json()
                asset = next(
                    (
                        item
                        for item in release["assets"]
                        if item["name"] == f"ui-{build}.zip"
                    ),
                    None,
                )
                if asset is None:
                    continue
                digest = str(asset.get("digest", "")).removeprefix("sha256:")
                if not BUILD.fullmatch(digest) or type(asset.get("id")) is not int:
                    raise ValueError("官方发布缺少前端校验信息")
                total = asset.get("size")
                calculated = hashlib.sha256()
                async with session.get(
                    f"{base}/assets/{asset['id']}",
                    headers={"Accept": "application/octet-stream"},
                    timeout=asset_download_timeout(total),
                ) as response:
                    response.raise_for_status()
                    state = self.states[build] = {
                        "phase": "download",
                        "received": 0,
                        "total": total,
                    }
                    with archive.open("xb") as output:
                        async for chunk in response.content.iter_chunked(65536):
                            state["received"] += len(chunk)
                            if state["received"] > ARCHIVE_LIMIT:
                                raise ValueError("前端压缩包超过下载上限")
                            calculated.update(chunk)
                            output.write(chunk)
                    if state["received"] != total or calculated.hexdigest() != digest:
                        raise ValueError("下载的前端与官方发布校验值不符")
                    return
        raise ValueError("官方构建尚未发布，请稍后重试")

    async def install(self, build):
        try:
            async with self.lock:
                self.reserve()
                with tempfile.TemporaryDirectory(
                    dir=self.root, prefix=".incoming-"
                ) as temp:
                    stage = Path(temp)
                    archive, content = stage / "ui.zip", stage / "ui"
                    content.mkdir()
                    await self.download(build, archive)
                    self.states[build] = {"phase": "verify"}
                    # Extraction must finish before cleaning up its workspace at shutdown.
                    worker = asyncio.create_task(
                        asyncio.to_thread(unpack, archive, content, build)
                    )
                    try:
                        await asyncio.shield(worker)
                    finally:
                        await worker
                    content.rename(self.directory(build))
                self.states.pop(build, None)
        except ValueError as exc:
            self.states[build] = {"phase": "error", "message": str(exc)}
        except TimeoutError:
            self.states[build] = {
                "phase": "error",
                "message": "从 GitHub 下载前端超时，请重试",
            }
        except Exception:
            self.states[build] = {
                "phase": "error",
                "message": "获取前端失败，请检查网关的 GitHub 连接或磁盘空间",
            }
        finally:
            self.jobs.pop(build, None)
            for key in set(self.states) - self.pinned() - self.jobs.keys():
                self.states.pop(key, None)

    async def close(self):
        jobs = list(self.jobs.values())
        for job in jobs:
            job.cancel()
        await asyncio.gather(*jobs, return_exceptions=True)
