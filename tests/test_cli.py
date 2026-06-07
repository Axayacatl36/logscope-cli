from typer.testing import CliRunner

from logscope.cli import app


runner = CliRunner()


def test_cli_context_outputs_neighboring_search_lines(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text(
        "\n".join(
            [
                "[INFO] service started",
                "[DEBUG] opening database connection",
                "[ERROR] payment failed for order 42",
                "[INFO] retry scheduled",
                "[INFO] healthcheck ok",
            ]
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [str(log_file), "--search", "payment failed", "--context", "1", "--no-color"],
    )

    assert result.exit_code == 0
    assert "opening database connection" in result.output
    assert "payment failed for order 42" in result.output
    assert "retry scheduled" in result.output
    assert "service started" not in result.output
    assert "healthcheck ok" not in result.output


def test_cli_rejects_context_without_search(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("[INFO] service started", encoding="utf-8")

    result = runner.invoke(app, [str(log_file), "--context", "1"])

    assert result.exit_code == 1
    assert "--context requires --search" in result.output
