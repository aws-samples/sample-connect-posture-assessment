#!/usr/bin/env python3
"""Generate docs/README.html from README.md with a clean standalone style."""

import sys
from pathlib import Path

try:
    import markdown
except ImportError:
    print("Install markdown: pip install markdown")
    sys.exit(1)

BASE = Path(__file__).parent.parent
md_content = (BASE / "README.md").read_text(encoding="utf-8")

html_body = markdown.markdown(
    md_content,
    extensions=["tables", "fenced_code", "toc"],
)

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Amazon Connect Assessment Tool — Documentation</title>
    <style>
        :root {
            --bg: #ffffff;
            --text: #16191f;
            --heading: #000716;
            --link: #0972d3;
            --code-bg: #f2f3f3;
            --border: #e9ebed;
            --accent: #ff9900;
            --table-header: #232f3e;
        }
        @media (prefers-color-scheme: dark) {
            :root {
                --bg: #16191f;
                --text: #d5dbdb;
                --heading: #ffffff;
                --link: #539fe5;
                --code-bg: #232f3e;
                --border: #414750;
                --table-header: #0f1b2a;
            }
        }
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                         "Helvetica Neue", Arial, sans-serif;
            font-size: 15px;
            line-height: 1.7;
            color: var(--text);
            background: var(--bg);
            max-width: 900px;
            margin: 0 auto;
            padding: 2rem 1.5rem;
        }
        h1, h2, h3, h4 { color: var(--heading); margin-top: 2rem; }
        h1 {
            font-size: 2rem;
            border-bottom: 3px solid var(--accent);
            padding-bottom: 0.5rem;
        }
        h2 {
            font-size: 1.5rem;
            border-bottom: 1px solid var(--border);
            padding-bottom: 0.3rem;
        }
        h3 { font-size: 1.2rem; }
        a { color: var(--link); text-decoration: none; }
        a:hover { text-decoration: underline; }
        code {
            font-family: "JetBrains Mono", "Fira Code", Menlo, monospace;
            font-size: 0.85em;
            background: var(--code-bg);
            padding: 0.15em 0.4em;
            border-radius: 4px;
        }
        pre {
            background: var(--code-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem;
            overflow-x: auto;
            font-size: 0.85em;
            line-height: 1.5;
        }
        pre code { background: none; padding: 0; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
            font-size: 0.9em;
        }
        th {
            background: var(--table-header);
            color: #ffffff;
            text-align: left;
            padding: 0.6rem 0.8rem;
        }
        td {
            padding: 0.5rem 0.8rem;
            border-bottom: 1px solid var(--border);
        }
        tr:nth-child(even) td { background: var(--code-bg); }
        hr {
            border: none;
            border-top: 1px solid var(--border);
            margin: 2rem 0;
        }
        blockquote {
            border-left: 4px solid var(--accent);
            margin: 1rem 0;
            padding: 0.5rem 1rem;
            background: var(--code-bg);
            border-radius: 0 8px 8px 0;
        }
        strong { color: var(--heading); }
        img { max-width: 100%; }
    </style>
</head>
<body>
BODY_PLACEHOLDER
</body>
</html>
"""

html_doc = HTML_TEMPLATE.replace("BODY_PLACEHOLDER", html_body)

output = BASE / "docs" / "README.html"
output.parent.mkdir(exist_ok=True)
output.write_text(html_doc, encoding="utf-8")
print(f"Generated {output} ({len(html_doc):,} chars)")
