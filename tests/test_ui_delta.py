import asyncio
import hashlib
import json
import struct
from zipfile import ZIP_DEFLATED, ZipFile

from aiohttp import web
from aiohttp.test_utils import TestServer

from mower_relay_server import ui_cache

A, B = "a" * 64, "b" * 64


def fixture(root, build):
    path = root / "release.zip"
    files = []
    with ZipFile(path, "w", ZIP_DEFLATED) as z:
        for name, data in {
            "relay-ui.json": json.dumps({"build": build}).encode(),
            "frontend-routes.json": b'["/"]',
            "index.html": b"new index",
            "logo.png": b"new logo",
            "assets/renamed.js": b"unchanged",
        }.items():
            z.writestr(name, data)
    archive = path.read_bytes()
    with ZipFile(path) as z:
        for f in z.infolist():
            lens = struct.unpack_from("<HH", archive, f.header_offset + 26)
            files.append(
                dict(
                    path=f.filename,
                    sha256=hashlib.sha256(z.read(f)).hexdigest(),
                    size=f.file_size,
                    method=f.compress_type,
                    length=f.compress_size,
                    offset=f.header_offset + 30 + sum(lens),
                )
            )
    manifest = dict(
        schema=1, build=build, archive=hashlib.sha256(archive).hexdigest(), files=files
    )
    return archive, manifest


def test_matching_contents_and_range_fallback(tmp_path, monkeypatch):
    async def run():
        archive, manifest = fixture(tmp_path, B)
        contents = {
            1: archive,
            2: json.dumps(manifest).encode(),
            3: json.dumps({"build": B}).encode(),
        }
        names = [f"ui-{B}.zip", f"ui-{B}.files.json", "channel-alpha.json"]
        assets = [
            dict(
                name=name,
                id=i,
                size=len(contents[i]),
                digest="sha256:" + hashlib.sha256(contents[i]).hexdigest(),
            )
            for i, name in enumerate(names, 1)
        ]
        requests = []
        mode = "ranges"

        async def release(request):
            return web.json_response({"assets": assets})

        async def asset(request):
            i = int(request.match_info["id"])
            data = contents[i]
            if i == 1:
                span = request.headers.get("Range")
                requests.append(span)
                if span and mode != "full":
                    start, end = map(int, span[6:].split("-"))
                    part = (
                        data[start : end + 1]
                        if mode == "ranges"
                        else b"x" * (end - start + 1)
                    )
                    return web.Response(
                        status=206,
                        body=part,
                        headers={"Content-Range": f"bytes {start}-{end}/{len(data)}"},
                    )
            return web.Response(body=data)

        routes = web.Application()
        base = "/ArkMowers/arknights-mower/releases"
        routes.router.add_get(base + "/tags/relay-ui", release)
        routes.router.add_get(base + "/assets/{id}", asset)
        async with TestServer(routes) as upstream:
            monkeypatch.setattr(
                ui_cache, "RELEASE_API", str(upstream.make_url("/")).rstrip("/")
            )
            for mode in ("ranges", "full", "corrupt"):
                requests.clear()
                cache = ui_cache.UiCache(tmp_path / mode, lambda: {A, B})
                old = cache.directory(A)
                old.mkdir(parents=True)
                (old / "logo.png").write_bytes(b"old logo")
                (old / "main.js").write_bytes(b"unchanged")
                (old / "removed.txt").write_bytes(b"removed")
                await cache.refresh_channels()
                await cache.jobs[B]
                assert cache.state(B)["phase"] == "ready"
                assert cache.channels == {"alpha": B}
                new = cache.directory(B)
                assert (new / "logo.png").read_bytes() == b"new logo"
                assert (old / "logo.png").read_bytes() == b"old logo"
                assert not (new / "removed.txt").exists()
                assert (new / "assets/renamed.js").read_bytes() == b"unchanged"
                if mode == "ranges":
                    assert requests and None not in requests
                    assert (old / "main.js").samefile(new / "assets/renamed.js")
                    reused = manifest["files"][-1]["offset"]
                    assert all(int(r.split("-")[1]) < reused for r in requests)
                else:
                    assert requests[-1] is None
                await cache.close()

    asyncio.run(run())


def test_eviction_keeps_channels_online_and_recent_idle(tmp_path):
    import os

    names = [f"{i:064x}" for i in range(7)]
    cache = ui_cache.UiCache(tmp_path, lambda: {names[0]})
    cache.channels = {"alpha": names[1], "stable": names[2]}
    for i, name in enumerate(names):
        folder = cache.directory(name)
        folder.mkdir()
        os.utime(folder, (i, i))
    cache.reserve()
    assert {p.name for p in tmp_path.iterdir()} == set(names[:3] + names[-2:])
