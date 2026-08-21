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
