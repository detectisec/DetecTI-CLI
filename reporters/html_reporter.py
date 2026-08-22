"""HTML Reporter for DetecTI Scans.

Converts the executive Markdown report into a modern, standalone HTML document
ready for direct browser interpretation, styling, and printing.
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import Optional

try:
    import markdown
    MARKDOWN_LIB_AVAILABLE = True
except ImportError:
    MARKDOWN_LIB_AVAILABLE = False

from core.models import ScanResult
from reporters.markdown_reporter import MarkdownReporter


class HTMLReporter:
    """Generates an executive, beautifully styled standalone HTML report from ScanResult."""

    HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DetecTI Security Intelligence Report - {target}</title>
    <style>
        :root {{
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --card-border: #30363d;
            --text-color: #c9d1d9;
            --text-heading: #f0f6fc;
            --accent-cyan: #58a6ff;
            --accent-blue: #1f6feb;
            --risk-critical: #f85149;
            --risk-high: #ff7b72;
            --risk-medium: #d29922;
            --risk-low: #3fb950;
            --table-row-alt: #1c2128;
            --code-bg: #21262d;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            padding: 2rem 1rem;
        }}

        .container {{
            max-width: 1100px;
            margin: 0 auto;
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 8px;
            padding: 2.5rem;
            box-shadow: 0 8px 24px rgba(0,0,0,0.5);
        }}

        .report-header {{
            border-bottom: 2px solid #30363d;
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }}

        .header-title-group h1 {{
            color: var(--accent-cyan);
            font-size: 1.8rem;
            font-weight: 700;
            margin-bottom: 0.25rem;
        }}

        .header-title-group .subtitle {{
            color: #8b949e;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .header-actions {{
            display: flex;
            gap: 0.5rem;
        }}

        .btn-print {{
            background: var(--code-bg);
            border: 1px solid var(--card-border);
            color: var(--text-heading);
            padding: 0.45rem 0.9rem;
            border-radius: 6px;
            font-size: 0.85rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }}

        .btn-print:hover {{
            background: var(--accent-blue);
            border-color: var(--accent-cyan);
            color: #ffffff;
        }}

        h1, h2, h3, h4, h5, h6 {{
            color: var(--text-heading);
            margin-top: 1.75rem;
            margin-bottom: 0.85rem;
            font-weight: 600;
        }}

        h1 {{ font-size: 1.75rem; color: var(--accent-cyan); border-bottom: 1px solid var(--card-border); padding-bottom: 0.4rem; }}
        h2 {{ font-size: 1.35rem; color: #79c0ff; border-bottom: 1px solid #21262d; padding-bottom: 0.3rem; margin-top: 2rem; }}
        h3 {{ font-size: 1.15rem; color: #a5d6ff; }}
        h4 {{ font-size: 1.05rem; color: #d2a8ff; }}
        h5 {{ font-size: 0.95rem; color: #ffa657; }}

        p {{
            margin-bottom: 1rem;
        }}

        blockquote {{
            border-left: 4px solid var(--accent-cyan);
            padding: 0.6rem 1rem;
            background: rgba(88, 166, 255, 0.08);
            margin: 1rem 0 1.5rem 0;
            border-radius: 0 6px 6px 0;
            color: #8b949e;
            font-size: 0.92rem;
        }}

        blockquote p {{
            margin-bottom: 0.3rem;
        }}

        blockquote p:last-child {{
            margin-bottom: 0;
        }}

        /* Table Styling */
        .table-wrapper {{
            overflow-x: auto;
            margin: 1rem 0 1.75rem 0;
            border: 1px solid var(--card-border);
            border-radius: 6px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.88rem;
            text-align: left;
        }}

        th {{
            background-color: #1f242c;
            color: #f0f6fc;
            padding: 0.75rem 0.9rem;
            font-weight: 600;
            border-bottom: 1px solid var(--card-border);
            white-space: nowrap;
        }}

        td {{
            padding: 0.65rem 0.9rem;
            border-bottom: 1px solid #21262d;
            vertical-align: middle;
        }}

        tr:nth-child(even) {{
            background-color: rgba(255, 255, 255, 0.02);
        }}

        tr:hover td {{
            background-color: rgba(88, 166, 255, 0.06);
        }}

        /* Code & Badges */
        code {{
            background-color: var(--code-bg);
            color: #79c0ff;
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, Liberation Mono, monospace;
            font-size: 0.85em;
            border: 1px solid rgba(110, 118, 129, 0.4);
        }}

        pre {{
            background-color: var(--code-bg);
            border: 1px solid var(--card-border);
            border-radius: 6px;
            padding: 1rem;
            overflow-x: auto;
            margin: 1rem 0;
        }}

        pre code {{
            background: none;
            border: none;
            padding: 0;
            color: var(--text-color);
        }}

        a {{
            color: var(--accent-cyan);
            text-decoration: none;
        }}

        a:hover {{
            text-decoration: underline;
        }}

        hr {{
            border: 0;
            height: 1px;
            background: var(--card-border);
            margin: 2rem 0;
        }}

        ul, ol {{
            padding-left: 1.75rem;
            margin-bottom: 1rem;
        }}

        li {{
            margin-bottom: 0.35rem;
        }}

        .footer-note {{
            margin-top: 3rem;
            text-align: center;
            font-size: 0.8rem;
            color: #8b949e;
            border-top: 1px solid var(--card-border);
            padding-top: 1.5rem;
        }}

        @media print {{
            body {{
                background: #ffffff;
                color: #000000;
                padding: 0;
            }}
            .container {{
                box-shadow: none;
                border: none;
                padding: 0;
                max-width: 100%;
            }}
            .btn-print {{
                display: none;
            }}
            th {{
                background: #f0f0f0;
                color: #000000;
            }}
            code {{
                background: #f5f5f5;
                color: #000000;
                border-color: #ccc;
            }}
            blockquote {{
                background: #f9f9f9;
                border-left-color: #007bff;
            }}
            h1, h2, h3, h4 {{
                color: #000000;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="report-header">
            <div class="header-title-group">
                <h1>DetecTI-CLI Intelligence Report</h1>
                <div class="subtitle">External Attack Surface Management &amp; Vulnerability Assessment &bull; <a href="https://detecti.com.br" target="_blank" rel="noopener noreferrer">detecti.com.br</a></div>
            </div>
            <div class="header-actions">
                <button class="btn-print" onclick="window.print()">🖨️ Print / Save PDF</button>
            </div>
        </div>

        <div class="report-body">
            {content}
        </div>

        <div class="footer-note">
            Generated automatically by <strong>DetecTI-CLI v2.0</strong> — External Attack Surface Mapping &amp; Threat Intelligence Engine.<br>
            Powered by <a href="https://detecti.com.br" target="_blank" rel="noopener noreferrer"><strong>DetecTI Security</strong> (detecti.com.br)</a>
        </div>
    </div>
</body>
</html>
"""

    @classmethod
    def generate(cls, result: ScanResult) -> str:
        """Generate standalone HTML document from ScanResult."""
        md_text = MarkdownReporter.generate(result)
        
        if MARKDOWN_LIB_AVAILABLE:
            html_body = markdown.markdown(
                md_text,
                extensions=["tables", "fenced_code", "nl2br", "sane_lists"]
            )
        else:
            # Simple fallback rendering if markdown package is missing
            lines = []
            for line in md_text.splitlines():
                if line.startswith("# "):
                    lines.append(f"<h1>{html.escape(line[2:])}</h1>")
                elif line.startswith("## "):
                    lines.append(f"<h2>{html.escape(line[3:])}</h2>")
                elif line.startswith("### "):
                    lines.append(f"<h3>{html.escape(line[4:])}</h3>")
                elif line.startswith("> "):
                    lines.append(f"<blockquote><p>{html.escape(line[2:])}</p></blockquote>")
                elif line.strip() == "---":
                    lines.append("<hr>")
                elif line.strip():
                    lines.append(f"<p>{html.escape(line)}</p>")
            html_body = "\n".join(lines)
        
        # Wrap tables in responsive wrapper div if not wrapped
        if "<table>" in html_body and '<div class="table-wrapper">' not in html_body:
            html_body = html_body.replace("<table>", '<div class="table-wrapper"><table>').replace("</table>", "</table></div>")

        safe_target = html.escape(str(result.target))
        return cls.HTML_TEMPLATE.format(target=safe_target, content=html_body)

    @classmethod
    def save(cls, result: ScanResult, output_path: Path | str) -> Path:
        """Save formatted HTML report to disk."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = cls.generate(result)
        path.write_text(content, encoding="utf-8")
        return path
