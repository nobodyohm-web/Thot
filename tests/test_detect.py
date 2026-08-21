from thot.scope.detect import detect_scope


def test_python_files_are_collected(toy_repo):
    manifest = detect_scope(toy_repo)
    assert "src/app.py" in manifest.files
    assert "src/safe.py" in manifest.files


def test_excluded_directories_are_skipped(toy_repo):
    manifest = detect_scope(toy_repo)
    assert not any(f.startswith("node_modules/") for f in manifest.files)


def test_languages_are_counted(toy_repo):
    manifest = detect_scope(toy_repo)
    assert manifest.languages["python"] == 2


def test_main_is_detected_as_entrypoint(toy_repo):
    manifest = detect_scope(toy_repo)
    assert "src.app.main" in manifest.entrypoints


def test_paths_are_relative_never_absolute(toy_repo):
    manifest = detect_scope(toy_repo)
    assert all(not f.startswith("/") for f in manifest.files)


# -- .thotignore -------------------------------------------------------------


def test_a_repository_can_exclude_what_it_did_not_write(tmp_path):
    """Vendored code produces noise that hides findings, not findings."""
    from thot.scope.detect import detect_scope

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1\n")
    (tmp_path / "vendored").mkdir()
    (tmp_path / "vendored" / "lib.py").write_text("y = 2\n")
    (tmp_path / ".thotignore").write_text("vendored/\n")

    files = detect_scope(tmp_path).files
    assert "src/app.py" in files
    assert "vendored/lib.py" not in files


def test_comments_and_blank_lines_are_not_patterns(tmp_path):
    from thot.scope.detect import load_ignore

    (tmp_path / ".thotignore").write_text("# rien\n\n  build/  \n")
    assert load_ignore(tmp_path) == ("build/",)


def test_ignore_patterns_behave_the_way_people_type_them():
    from thot.scope.detect import is_ignored

    patterns = ("skills/", "*.generated.py", "fixtures")

    assert is_ignored("skills/a/b.py", patterns)
    assert is_ignored("skills/x.py", patterns)
    assert is_ignored("src/client.generated.py", patterns)
    # A bare name matches at any depth, the way gitignore does.
    assert is_ignored("tests/fixtures/broken.py", patterns)

    assert not is_ignored("src/skillset.py", patterns)
    assert not is_ignored("src/app.py", patterns)


def test_no_ignore_file_means_no_patterns(tmp_path):
    from thot.scope.detect import load_ignore

    assert load_ignore(tmp_path) == ()


def test_thot_excludes_its_own_ported_library():
    """The port made Thot's own audit unreadable; this is why the file exists."""
    from pathlib import Path

    from thot.scope.detect import load_ignore

    patterns = load_ignore(Path(__file__).resolve().parents[1])
    assert "skills/" in patterns
    assert "optional-skills/" in patterns
