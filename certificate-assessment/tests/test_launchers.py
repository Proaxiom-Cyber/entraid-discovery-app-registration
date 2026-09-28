"""Run the launchers against a local stub; no authentication or tenant access."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def launchers(tmp_path):
    folder = tmp_path / "path with spaces"
    folder.mkdir()
    for name in ("setup.sh", "Setup-AssessmentApp.ps1"):
        shutil.copyfile(ROOT / name, folder / name)
    (folder / "Sync-AssessmentApp.ps1").write_text(
        "param([string]$Config, [switch]$Preview, [switch]$Apply)\n"
        "if ($Config -eq 'fail config.json') { throw 'Sanitized engine failure' }\n"
        "$global:LASTEXITCODE = 23 # A stale native result must not become this script's result.\n"
        "@{config=$Config;preview=$Preview.IsPresent;apply=$Apply.IsPresent} | ConvertTo-Json -Compress\n"
        "return\n", encoding="utf-8")
    return folder


@pytest.mark.skipif(shutil.which("sh") is None or shutil.which("pwsh") is None,
                    reason="POSIX shell and PowerShell 7 are required")
@pytest.mark.parametrize("mode", [[], ["--preview"], ["--apply"]])
def test_shell_preserves_arguments_and_exit_status(launchers, mode):
    result = subprocess.run(["sh", (launchers / "setup.sh").as_posix(), "--config",
                             "config with spaces.json", *mode], capture_output=True, text=True)
    assert result.returncode == 0
    assert json.loads(result.stdout) == {"config": "config with spaces.json",
                                         "preview": "--preview" in mode, "apply": "--apply" in mode}


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 is required")
@pytest.mark.parametrize("mode", [None, "-Preview", "-Apply"])
def test_powershell_preserves_arguments_and_exit_status(launchers, mode):
    command = ["pwsh", "-NoProfile", "-File", str(launchers / "Setup-AssessmentApp.ps1"),
               "-Config", "config with spaces.json"]
    if mode:
        command.append(mode)
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0
    assert json.loads(result.stdout) == {"config": "config with spaces.json",
                                         "preview": mode == "-Preview", "apply": mode == "-Apply"}


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 is required")
def test_powershell_refuses_conflicting_modes(launchers):
    result = subprocess.run(["pwsh", "-NoProfile", "-File",
                             str(launchers / "Setup-AssessmentApp.ps1"), "-Config", "config.json",
                             "-Preview", "-Apply"],
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert result.stdout == ""


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 is required")
@pytest.mark.parametrize("launcher", ["powershell", "shell"])
def test_engine_throw_returns_failure(launchers, launcher):
    if launcher == "shell":
        if shutil.which("sh") is None:
            pytest.skip("POSIX shell is required")
        command = ["sh", (launchers / "setup.sh").as_posix(), "--config", "fail config.json"]
    else:
        command = ["pwsh", "-NoProfile", "-File", str(launchers / "Setup-AssessmentApp.ps1"),
                   "-Config", "fail config.json"]
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode != 0
    assert result.stdout == ""


@pytest.mark.skipif(shutil.which("sh") is None, reason="POSIX shell is required")
@pytest.mark.parametrize("arguments", [[], ["--config"], ["--unknown"],
    ["--config", "config.json", "--preview", "--apply"],
    ["--config", "one.json", "--config", "two.json"]])
def test_shell_refuses_invalid_arguments_before_engine(launchers, arguments):
    result = subprocess.run(["sh", (launchers / "setup.sh").as_posix(), *arguments],
                            capture_output=True, text=True)
    assert result.returncode == 2
    assert result.stdout == ""
