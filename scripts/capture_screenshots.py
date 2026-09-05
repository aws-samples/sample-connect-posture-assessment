#!/usr/bin/env python3
"""Capture documentation screenshots from the sample assessment reports.

Install the optional screenshot dependencies before running this script:

    pip install -e ".[screenshots]"
    playwright install chromium

The default invocation captures the top of the checked-in sample report:

    python scripts/capture_screenshots.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT = REPO_ROOT / "examples" / "sample_assessment_report.html"
DEFAULT_OUTPUT = REPO_ROOT / "docs" / "images" / "sample-assessment-report.png"


def parse_args() -> argparse.Namespace:
    """Parse command-line options for the screenshot workflow."""
    parser = argparse.ArgumentParser(
        description="Capture a screenshot from an HTML assessment report."
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=DEFAULT_REPORT,
        help=f"HTML report to capture (default: {DEFAULT_REPORT})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"PNG output path (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument("--width", type=int, default=1440, help="Viewport width in pixels.")
    parser.add_argument("--height", type=int, default=900, help="Viewport height in pixels.")
    parser.add_argument(
        "--scroll-y",
        type=int,
        default=0,
        help="Vertical scroll position before capture (default: 0).",
    )
    parser.add_argument(
        "--dark-mode",
        action="store_true",
        help="Enable the report's dark mode before capture.",
    )
    parser.add_argument(
        "--full-page",
        action="store_true",
        help="Capture the complete report instead of the viewport.",
    )
    parser.add_argument(
        "--wait-ms",
        type=int,
        default=1500,
        help="Time to wait for charts and client-side rendering (default: 1500).",
    )
    parser.add_argument(
        "--no-optimize",
        action="store_true",
        help="Skip Pillow PNG optimization after capture.",
    )
    return parser.parse_args()


def _load_dependencies() -> tuple[Any, Any]:
    """Import optional browser dependencies with an actionable error."""
    try:
        from PIL import Image
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise SystemExit(
            "Screenshot dependencies are missing. Install them with:\n"
            '  pip install -e ".[screenshots]"\n'
            "  playwright install chromium"
        ) from exc
    return Image, sync_playwright


def _validate_args(args: argparse.Namespace) -> None:
    """Reject invalid paths and viewport values before launching a browser."""
    if not args.report.is_file():
        raise SystemExit(f"Report file not found: {args.report}")
    if args.width <= 0 or args.height <= 0:
        raise SystemExit("Viewport width and height must be positive integers.")
    if args.scroll_y < 0:
        raise SystemExit("Scroll position must be zero or greater.")
    if args.wait_ms < 0:
        raise SystemExit("Wait time must be zero or greater.")


def _prepare_page(page: Any, args: argparse.Namespace) -> None:
    """Load the report and apply deterministic state before capturing it."""
    page.goto(args.report.resolve().as_uri(), wait_until="domcontentloaded")
    page.wait_for_selector(".report-header", timeout=10_000)
    page.wait_for_timeout(args.wait_ms)

    if args.dark_mode:
        toggle = page.locator(".dark-mode-toggle")
        if toggle.count() == 0:
            raise RuntimeError("The report does not expose a dark-mode toggle.")
        if not page.locator("body.dark-mode").count():
            toggle.click()
            page.wait_for_timeout(250)

    page.evaluate("(scrollY) => window.scrollTo(0, scrollY)", args.scroll_y)
    page.wait_for_timeout(100)


def _optimize_png(image_path: Path, image_module: Any) -> None:
    """Apply lossless PNG optimization while preserving the documentation format."""
    with image_module.open(image_path) as image:
        if image.mode in {"RGBA", "P"}:
            image = image.convert("RGB")
        image.save(image_path, format="PNG", optimize=True)


def capture(args: argparse.Namespace) -> Path:
    """Capture and optionally optimize one report screenshot."""
    image_module, sync_playwright = _load_dependencies()
    args.output.parent.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            page = browser.new_page(viewport={"width": args.width, "height": args.height})
            _prepare_page(page, args)
            page.screenshot(path=str(args.output), full_page=args.full_page)
        finally:
            browser.close()

    if not args.no_optimize:
        _optimize_png(args.output, image_module)
    return args.output


def main() -> int:
    """Run the screenshot capture command."""
    args = parse_args()
    _validate_args(args)
    try:
        output = capture(args)
    except RuntimeError as exc:
        print(f"Screenshot capture failed: {exc}", file=sys.stderr)
        return 1
    print(f"Screenshot captured: {output} ({output.stat().st_size / 1024:.1f} KiB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
