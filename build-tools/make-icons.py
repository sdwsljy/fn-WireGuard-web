# -*- coding: utf-8 -*-
"""生成 fn-wg-web 应用图标：深色渐变底 + 主色节点与链路光束。"""
from PIL import Image, ImageDraw

def draw_icon(size: int, path: str) -> None:
    scale = size / 256.0
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # 圆角方形背景（深色垂直渐变）
    radius = int(size * 0.2)
    mask = Image.new("L", (size, size), 0)
    md = ImageDraw.Draw(mask)
    md.rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=255)

    top = (22, 42, 70, 255)
    bottom = (8, 13, 24, 255)
    for y in range(size):
        t = y / max(size - 1, 1)
        color = tuple(int(top[i] * (1 - t) + bottom[i] * t) for i in range(4))
        d.line([(0, y), (size, y)], fill=color)
    img.putalpha(mask)

    cx, cy = size * 0.5, size * 0.5
    accent = (45, 212, 167, 255)
    accent_bright = (52, 224, 178, 255)

    # 中心节点
    node_r = size * 0.135
    d.ellipse([cx - node_r, cy - node_r, cx + node_r, cy + node_r], fill=accent)
    core_r = size * 0.055
    d.ellipse([cx - core_r, cy - core_r, cx + core_r, cy + core_r], fill=(6, 37, 29, 255))

    # 四条光束（双线 = 链路感）
    beam = size * 0.058
    gap = size * 0.21
    length = size * 0.30
    lw = max(2, int(size * 0.035))
    beam_color = (45, 212, 167, 200)
    tip_r = size * 0.028
    for dx, dy in [(0, -1), (0, 1), (-1, 0), (1, 0)]:
        # 两条平行线
        for off in (-beam * 0.4, beam * 0.4):
            x0 = cx + (off if dx != 0 else 0)
            y0 = cy + (off if dy != 0 else 0)
            x1 = x0 + dx * length
            y1 = y0 + dy * length
            if dx == 0:
                x0 += dx
                x1 += dx
            if dy == 0:
                y0 += dy
                y1 += dy
            d.line([(x0, y0), (x1, y1)], fill=beam_color, width=lw)
        # 末端端点
        for off in (-beam * 0.4, beam * 0.4):
            ex = cx + (off if dx != 0 else 0) + dx * length
            ey = cy + (off if dy != 0 else 0) + dy * length
            d.ellipse([ex - tip_r, ey - tip_r, ex + tip_r, ey + tip_r], fill=accent_bright)

    # 中心节点上叠加半透明高光
    hl = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    hd = ImageDraw.Draw(hl)
    hd.ellipse([cx - node_r * 0.75, cy - node_r * 0.85, cx + node_r * 0.55, cy + node_r * 0.35], fill=(255, 255, 255, 40))
    img.alpha_composite(hl)

    img.save(path, "PNG")
    print("icon: %s (%d x %d)" % (path, size, size))

if __name__ == "__main__":
    import os
    root = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "pkg", "fnos"
    )
    for name, size in [("ICON.PNG", 64), ("ICON_256.PNG", 256)]:
        draw_icon(size, os.path.join(root, name))
    os.makedirs(os.path.join(root, "ui", "images"), exist_ok=True)
    draw_icon(256, os.path.join(root, "ui", "images", "256.png"))
    draw_icon(64, os.path.join(root, "ui", "images", "64.png"))
    # 桌面图标固定名（ui/config 中 icon 字段引用）
    draw_icon(128, os.path.join(root, "ui", "images", "icon.png"))
