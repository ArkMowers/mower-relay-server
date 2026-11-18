"""Reconstruct an immutable frontend using verified cached files and ZIP ranges."""

import asyncio
import hashlib
import os
import re
import shutil
import zlib
from pathlib import PurePosixPath, PureWindowsPath


def safe_path(name):
    path = PurePosixPath(name)
    if (
        not path.parts
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in name
        or ":" in name
        or any(
            part.rstrip(". ") != part or PureWindowsPath(part).is_reserved()
            for part in path.parts
        )
    ):
        raise ValueError("前端包路径无效")
    return path


def members(manifest, build, digest, archive_size, limit):
    if (
        manifest.get("schema") != 1
        or manifest.get("build") != build
        or manifest.get("archive") != digest
    ):
        raise ValueError("前端文件清单与发布包不匹配")
    files = manifest["files"]
    if not isinstance(files, list) or not 0 < len(files) <= 8192:
        raise ValueError("前端文件清单无效")
    names = set()
    end = total = 0
    for item in sorted(files, key=lambda entry: entry["offset"]):
        path = safe_path(item["path"])
        key = str(path).casefold()
        offset, length, size = (item[k] for k in ("offset", "length", "size"))
        if (
            key in names
            or any(type(v) is not int or v < 0 for v in (offset, length, size))
            or offset < end
            or offset + length > archive_size
            or item["method"] not in (0, 8)
            or not re.fullmatch("[0-9a-f]{64}", item["sha256"])
        ):
            raise ValueError("前端清单条目无效")
        names.add(key)
        end = offset + length
        total += size
        if total > limit:
            raise ValueError("前端文件超过缓存限制")
    return sorted(files, key=lambda entry: entry["offset"])


def cached_files(directories, sizes):
    cached = {}
    seen = set()
    for directory in directories:
        for path in directory.rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue
            info = path.stat()
            identity = (info.st_dev, info.st_ino)
            if info.st_size not in sizes or identity in seen:
                continue
            seen.add(identity)
            with path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            cached[digest] = path
    return cached


def link_file(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(source, target)
    except OSError:
        shutil.copyfile(source, target)


def range_groups(files, cached):
    groups = []
    pending = []
    for item in files:
        if item["sha256"] in cached or not item["length"]:
            if pending:
                groups.append(pending)
                pending = []
        else:
            if pending:
                last = pending[-1]
                if item["offset"] - (last["offset"] + last["length"]) > 4096:
                    groups.append(pending)
                    pending = []
            pending.append(item)
    if pending:
        groups.append(pending)
    return groups


def write_member(directory, item, compressed):
    data = compressed
    if item["method"] == 8:
        decoder = zlib.decompressobj(-15)
        data = decoder.decompress(compressed, item["size"] + 1)
        if not decoder.eof or decoder.unused_data:
            raise ValueError("前端文件解压失败")
    if len(data) != item["size"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
        raise ValueError("前端文件校验失败")
    target = directory / item["path"]
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as output:
        output.write(data)


async def reconstruct(files, cached, directory, fetch, state):
    if not any(item["sha256"] in cached for item in files):
        return False
    groups = range_groups(files, cached)
    state.update(
        phase="download",
        received=0,
        total=sum(g[-1]["offset"] + g[-1]["length"] - g[0]["offset"] for g in groups),
    )
    for group in groups:
        start = group[0]["offset"]
        end = group[-1]["offset"] + group[-1]["length"]
        data = await fetch(start, end)
        await finish_io(write_group, directory, group, start, data)
    await finish_io(reuse_files, files, cached, directory)
    return True


def write_group(directory, group, start, data):
    for item in group:
        pos = item["offset"] - start
        write_member(directory, item, data[pos : pos + item["length"]])


def reuse_files(files, cached, directory):
    for item in files:
        source = cached.get(item["sha256"])
        if source is not None:
            link_file(source, directory / item["path"])
        elif not item["length"]:
            write_member(directory, item, b"")


async def finish_io(function, *args):
    # The temporary directory must outlive writes that are already running.
    worker = asyncio.create_task(asyncio.to_thread(function, *args))
    try:
        return await asyncio.shield(worker)
    finally:
        await worker
