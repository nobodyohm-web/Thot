import pytest

from thot.errors import AuthorizationError
from thot.scope.authorization import load_authorization, write_authorization


def test_missing_file_is_refused(tmp_path):
    with pytest.raises(AuthorizationError, match="autorisation"):
        load_authorization(tmp_path)


def test_written_file_is_accepted(tmp_path):
    write_authorization(tmp_path, owner="Dev")
    auth = load_authorization(tmp_path)
    assert auth.owner == "Dev"
    assert auth.authorized is True


def test_authorized_false_is_refused(tmp_path):
    path = write_authorization(tmp_path, owner="Dev")
    path.write_text(path.read_text().replace("authorized: true", "authorized: false"))
    with pytest.raises(AuthorizationError, match="authorized"):
        load_authorization(tmp_path)


def test_scope_mismatch_is_refused(tmp_path):
    write_authorization(tmp_path, owner="Dev")
    other = tmp_path / "elsewhere"
    other.mkdir()
    (other / ".thot").mkdir()
    (other / ".thot" / "authorization.yaml").write_text(
        "owner: Dev\nscope: /not/this/path\nauthorized: true\ndate: '2026-08-21'\n"
    )
    with pytest.raises(AuthorizationError, match="périmètre"):
        load_authorization(other)
