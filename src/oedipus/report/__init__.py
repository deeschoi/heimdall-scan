from oedipus.report import json_report, markdown, sarif


def render(fmt: str, findings, target: str = "") -> str:
    if fmt == "json":
        return json_report.render(findings, target)
    if fmt == "sarif":
        return sarif.render(findings, target)
    if fmt in ("md", "markdown"):
        return markdown.render(findings, target)
    raise ValueError(f"Unknown report format: {fmt}")


__all__ = ["render", "json_report", "sarif", "markdown"]
