from click.testing import CliRunner as ClickCliRunner
from typer.testing import CliRunner as TyperCliRunner


if not hasattr(TyperCliRunner, "isolated_filesystem"):
    TyperCliRunner.isolated_filesystem = ClickCliRunner.isolated_filesystem
