from thot import cli


def test_version_flag_prints_version_and_exits_zero(capsys):
    code = cli.main(["--version"])
    captured = capsys.readouterr()
    assert code == 0
    assert "thot" in captured.out.lower()


def test_no_command_shows_help_and_exits_two(capsys):
    code = cli.main([])
    captured = capsys.readouterr()
    assert code == 2
    assert "audit" in captured.out
