# -*- coding: utf-8 -*-
"""fn-wg-web fpk 打包器（纯标准库，Windows/Linux 通用）

生成 fnOS 可安装的 .fpk 应用包：
  fn-wg-web_0.2.9_all.fpk (tar.gz)
  ├── manifest / ICON.PNG / ICON_256.PNG
  ├── app.tgz   (wg-manager.py + web/)
  ├── cmd/      (main + *_init + *_callback)
  ├── config/   (privilege + resource)
  └── ui/       (config + index.cgi + images/)
"""
import gzip
import io
import os
import shutil
import tarfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES_DIR = os.path.join(ROOT, "pkg", "files")
FNOS_DIR = os.path.join(ROOT, "pkg", "fnos")
DIST_DIR = os.path.join(ROOT, "dist")
VERSION = "0.2.9"
APPNAME = "fn-wg-web"
PKG = "%s_%s_all.fpk" % (APPNAME, VERSION)

EXEC_NAMES = {
    "cmd/main", "cmd/install_init", "cmd/install_callback",
    "cmd/config_init", "cmd/config_callback",
    "cmd/uninstall_init", "cmd/uninstall_callback",
    "cmd/upgrade_init", "cmd/upgrade_callback",
    "ui/index.cgi",
}


def add_tree(tf, src, arc_prefix=""):
    """递归将 src 加入 tar，控制可执行位。"""
    for cur, _dirs, files in os.walk(src):
        _dirs[:] = [d for d in _dirs if d != "__pycache__"]
        rel = os.path.relpath(cur, src)
        for f in files:
            if f.endswith(".pyc") or f.endswith(".pyo"):
                continue
            full = os.path.join(cur, f)
            arc = os.path.join(arc_prefix, rel, f) if rel != "." else os.path.join(arc_prefix, f)
            arc = arc.replace(os.sep, "/")
            mode = 0o755 if (arc in EXEC_NAMES or arc == "wg-manager.py") else 0o644
            info = tf.gettarinfo(full, arcname=arc)
            info.mode = mode
            with open(full, "rb") as fh:
                tf.addfile(info, fh)


def make_gzip_tar(arcname, src, out_path, as_member):
    """把 src（文件或目录）打包成单独 gzip，作为 fpk 里的 as_member。"""
    with open(out_path, "wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w") as tf:
                if os.path.isfile(src):
                    info = tf.gettarinfo(src, arcname=arcname)
                    with open(src, "rb") as fh:
                        tf.addfile(info, fh)
                else:
                    add_tree(tf, src, arcname)


def main():
    if os.path.isdir(DIST_DIR):
        shutil.rmtree(DIST_DIR)
    os.makedirs(DIST_DIR, exist_ok=True)
    stage = os.path.join(DIST_DIR, "stage")
    if os.path.isdir(stage):
        shutil.rmtree(stage)
    os.makedirs(stage)

    # 1. app.tgz（wg-manager.py + web/ + ui/）
    app_tgz = os.path.join(stage, "app.tgz")
    with open(app_tgz, "wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w") as tf:
                add_tree(tf, FILES_DIR, "")
                add_tree(tf, os.path.join(FNOS_DIR, "ui"), "ui")

    # 2. 复制清单 / 图标 / cmd / config / ui
    for name in ("manifest", "ICON.PNG", "ICON_256.PNG"):
        shutil.copy2(os.path.join(FNOS_DIR, name), os.path.join(stage, name))
    for name in ("cmd", "config", "ui"):
        shutil.copytree(os.path.join(FNOS_DIR, name), os.path.join(stage, name))

    # 3. 打包 fpk
    out_fpk = os.path.join(DIST_DIR, PKG)
    members = ["manifest", "app.tgz", "cmd", "config", "ICON.PNG", "ICON_256.PNG", "ui"]
    with open(out_fpk, "wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w") as tf:
                for m in members:
                    src = os.path.join(stage, m)
                    if os.path.isfile(src):
                        info = tf.gettarinfo(src, arcname=m)
                        with open(src, "rb") as fh:
                            tf.addfile(info, fh)
                    else:
                        add_tree(tf, src, m)

    shutil.rmtree(stage)
    size_kb = os.path.getsize(out_fpk) / 1024.0
    print("OK -> %s (%.1f KB)" % (out_fpk, size_kb))
    print("Install: fnOS App Center -> Manual install -> select this fpk file")


if __name__ == "__main__":
    main()
