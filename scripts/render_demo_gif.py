#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "assets" / "veil-mcp-demo.gif"

LINES = [
    "$ python scripts/smoke_mcp_proxy.py --show-stderr",
    "PASS initialize passes through",
    "PASS tools/list filters poisoned tools",
    "PASS safe read_file call passes",
    "PASS secret file call is blocked",
    "PASS blocked call includes Veil findings",
    "PASS exfiltration tool call is blocked",
    "PASS audit log written",
    "PASS audit log records blocks",
    "",
    "--- proxy stderr ---",
    "[veil-mcp] blocked descriptor demo.write_file",
    "  mcp_policy:tool_blocked, prompt_injection:instruction_override",
    "[malicious-demo] upstream received tools/call read_file",
    '  {"path": "/safe/readme.md"}',
    "[veil-mcp] blocked call demo.read_file",
    "  mcp_policy:path_blocked, mcp_policy:sensitive_path",
    "[veil-mcp] blocked call demo.exfiltrate_context",
    "  mcp_policy:domain_blocked, prompt_injection:data_exfiltration",
    "",
    "Veil MCP proxy smoke demo passed.",
]


def main() -> int:
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError as exc:
        raise SystemExit("Pillow is required to render the demo GIF.") from exc

    width = 1000
    height = 560
    pad = 28
    chrome_h = 42
    line_h = 22
    bg = "#0e1117"
    terminal = "#161b22"
    border = "#30363d"
    text = "#c9d1d9"
    muted = "#8b949e"
    green = "#7ee787"
    red = "#ff7b72"
    amber = "#d29922"
    blue = "#79c0ff"

    font_path = "/System/Library/Fonts/SFNSMono.ttf"
    title_font_path = "/System/Library/Fonts/SFNS.ttf"
    font = ImageFont.truetype(font_path, 16)
    title_font = ImageFont.truetype(title_font_path, 15)

    def draw_frame(visible_lines: list[str]) -> Image.Image:
        img = Image.new("RGB", (width, height), bg)
        draw = ImageDraw.Draw(img)
        draw.rounded_rectangle((pad, pad, width - pad, height - pad), radius=12, fill=terminal, outline=border, width=2)
        draw.rounded_rectangle((pad, pad, width - pad, pad + chrome_h), radius=12, fill="#21262d")
        draw.rectangle((pad, pad + chrome_h - 10, width - pad, pad + chrome_h), fill="#21262d")

        x = pad + 18
        y = pad + 16
        for i, color in enumerate(("#ff5f56", "#ffbd2e", "#27c93f")):
            draw.ellipse((x + i * 22, y, x + 12 + i * 22, y + 12), fill=color)
        draw.text((pad + 118, pad + 13), "veil-mcp demo", fill=muted, font=title_font)

        y = pad + chrome_h + 24
        x = pad + 22
        for line in visible_lines:
            color = text
            if line.startswith("$"):
                color = blue
            elif line.startswith("PASS"):
                color = green
            elif line.startswith("[veil-mcp] blocked"):
                color = red
            elif line.startswith("[malicious-demo]"):
                color = amber
            elif line.startswith("---"):
                color = muted
            elif line.startswith("  "):
                color = muted
            draw.text((x, y), line, fill=color, font=font)
            y += line_h
        return img

    frames: list[Image.Image] = []
    durations: list[int] = []

    for idx in range(1, len(LINES) + 1):
        frames.append(draw_frame(LINES[:idx]))
        durations.append(170 if idx < len(LINES) else 1800)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    frames[0].save(
        OUT,
        save_all=True,
        append_images=frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
    )
    print(OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
