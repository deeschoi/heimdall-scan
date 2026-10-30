"""`heimdall --version` prints the title banner."""

from click.testing import CliRunner

from heimdall import __version__
from heimdall.cli import main


def test_version_banner():
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "/_/ /_/\\___/_/_/ /_/ /_/\\__,_/\\__,_/_/_/" in result.output
    assert f"v{__version__}" in result.output
    assert result.output.rstrip().endswith("github.com/deeschoi")
    # The author line is the first column, under the left edge of the wordmark.
    assert "\ngithub.com/deeschoi" in result.output
