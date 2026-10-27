from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys

import pytest

from metis_firmware_campaign import autonomous_campaign as metis_campaign


STANDALONE = (
    Path(__file__).resolve().parents[2]
    / "portable-firmware-campaign/.agents/skills/firmware-finding-pipeline/scripts/autonomous_campaign.py"
)


def implementations():
    sys.path.insert(0, str(STANDALONE.parent))
    spec = importlib.util.spec_from_file_location("pending_standalone", STANDALONE)
    standalone = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(standalone)
    return (("metis", metis_campaign), ("standalone", standalone))


def retained_state(path: Path) -> list[tuple[str, str, bytes | str]]:
    result = []
    for item in sorted(path.rglob("*")):
        relative = item.relative_to(path).as_posix()
        if item.is_symlink():
            result.append((relative, "symlink", item.readlink().as_posix()))
        elif item.is_file():
            result.append((relative, "file", item.read_bytes()))
        elif item.is_dir():
            result.append((relative, "directory", ""))
    return result


DRIVER = r'''
import importlib.util,json,os,pathlib,sys,time
cfg=json.loads(pathlib.Path(sys.argv[1]).read_text())
if cfg["implementation"]=="metis":
 from metis_firmware_campaign import autonomous_campaign as implementation
else:
 sys.path.insert(0,str(pathlib.Path(cfg["implementation_path"]).parent))
 spec=importlib.util.spec_from_file_location("driver_standalone",cfg["implementation_path"]);implementation=importlib.util.module_from_spec(spec);spec.loader.exec_module(implementation)
candidate=pathlib.Path(cfg["candidate"]);state=pathlib.Path(cfg["state"]);stage=cfg["stage"]
original=implementation.os.replace;fired=False
def replace(source,destination):
 global fired
 source=pathlib.Path(source);destination=pathlib.Path(destination)
 event=None
 if destination==candidate and source.name=="candidate-stage.db":event="candidate"
 if destination.parent==state/"stages"/stage["stage_id"] and source.parent==state/"stages" and source.name.startswith("."+stage["stage_id"]+"."):event="receipt"
 if destination.name=="result" and destination.is_relative_to(state/"failed-pending-commits"):event="fallback-result"
 if destination.name=="control" and destination.is_relative_to(state/"failed-pending-commits"):event="fallback-control"
 if destination.name=="recovery.json" and source.name.startswith(".recovery.json.") and destination.is_relative_to(state/"failed-pending-commits"):event="fallback-record"
 if destination.name==cfg.get("pending_content_hash") and source.name.startswith("."+cfg.get("pending_content_hash","")+".preparing."):event="fallback-archive"
 if destination==candidate and source.name.startswith(".candidate-restore."):event="fallback-restore"
 if not fired and event=="candidate" and cfg["fault"]=="hold-candidate":
  pathlib.Path(cfg["ready"]).write_text("ready");deadline=time.monotonic()+15
  while not pathlib.Path(cfg["release"]).exists():
   if time.monotonic()>deadline:raise RuntimeError("writer hold timed out")
   time.sleep(.02)
 if not fired and event and cfg["fault"].startswith(event):
  fired=True
  if cfg["fault"].endswith("after"):original(source,destination)
  os._exit(97)
 original(source,destination)
implementation.os.replace=replace
profile_path=pathlib.Path(cfg["profile"]);profile=json.loads(profile_path.read_text());identity={"locator":str(profile_path),"sha256":implementation.file_hash(profile_path)}
if cfg["action"]=="execute":implementation.execute_stage(stage,profile,identity,state,candidate,{}, {}, {}, {})
else:implementation.recover_pending_commits(state,candidate,profile,identity)
'''


ADAPTER = r'''
import json,os,pathlib,sqlite3
context=json.loads(pathlib.Path(os.environ["FIRMWARE_CAMPAIGN_CONTEXT"]).read_text());candidate=context["candidate_path"];output=pathlib.Path(context["output_directory"])
with sqlite3.connect(candidate) as db:db.execute("CREATE TABLE IF NOT EXISTS committed(value TEXT)");db.execute("INSERT INTO committed VALUES('policy')")
(output/"result.json").write_text('{"ok":true}\n')
'''


def setup(root: Path, name: str) -> tuple[dict, Path, Path, Path, Path]:
    root.mkdir()
    candidate = root / "candidate.db"
    with sqlite3.connect(candidate) as database:
        database.execute("CREATE TABLE baseline(value TEXT)")
        database.execute("INSERT INTO baseline VALUES('fixed')")
    adapter = root / "adapter.py"
    adapter.write_text(ADAPTER)
    profile_path = root / "profile.json"
    profile = {
        "schema_version": "3",
        "project": {"project_id": "pending-fixture"},
        "automation": {
            "campaign_reader_limit": 1,
            "provider_worker_configuration_limit": 1,
            "stages": [],
        },
    }
    profile_path.write_text(json.dumps(profile, sort_keys=True) + "\n")
    stage = {
        "stage_id": "build",
        "phase": "CANDIDATE_BUILD",
        "adapter": [sys.executable, str(adapter)],
        "required_outputs": ["result.json"],
    }
    profile["automation"]["stages"] = [stage]
    profile_path.write_text(json.dumps(profile, sort_keys=True) + "\n")
    state = root / "state"
    driver = root / "driver.py"
    driver.write_text(DRIVER)
    return stage, candidate, state, profile_path, driver


def drive(
    root: Path,
    name: str,
    stage: dict,
    candidate: Path,
    state: Path,
    profile: Path,
    driver: Path,
    action: str,
    fault: str,
    pending_content_hash: str | None = None,
) -> subprocess.CompletedProcess[str]:
    configuration = root / f"{action}-{fault}.json"
    configuration.write_text(
        json.dumps(
            {
                "action": action,
                "candidate": str(candidate),
                "fault": fault,
                "implementation": name,
                "implementation_path": str(STANDALONE),
                "pending_content_hash": pending_content_hash,
                "profile": str(profile),
                "stage": stage,
                "state": str(state),
            },
            sort_keys=True,
        )
        + "\n"
    )
    return subprocess.run([sys.executable, str(driver), str(configuration)], text=True)


def pending(state: Path) -> tuple[Path, dict]:
    path = next(state.glob(".candidate-*/pending-commit.json"))
    return path, json.loads(path.read_text())


@pytest.mark.parametrize("fault", ("candidate-after", "receipt-before"))
def test_crash_window_completes_bound_candidate_without_replay(
    tmp_path: Path, fault: str
) -> None:
    for name, implementation in implementations():
        root = tmp_path / f"{name}-{fault}"
        stage, candidate, state, profile_path, driver = setup(root, name)
        interrupted = drive(root, name, stage, candidate, state, profile_path, driver, "execute", fault)
        assert interrupted.returncode == 97
        marker, commitment = pending(state)
        expected = commitment["candidate_after"]
        before_recovery = implementation.candidate_state(candidate)
        if fault == "candidate-after":
            assert before_recovery == expected
        result = implementation.recover_pending_commits(
            state,
            candidate,
            json.loads(profile_path.read_text()),
            {"locator": str(profile_path), "sha256": implementation.file_hash(profile_path)},
        )
        assert result[0]["result"] == "PENDING_COMMIT_COMPLETED"
        assert implementation.candidate_state(candidate) == expected
        assert not marker.exists()
        receipt = implementation.completed_receipt(
            state, stage["stage_id"], commitment["receipt_sha256"]
        )
        assert receipt["candidate_after"] == expected


def test_repeated_recovery_interruptions_remain_restartable(tmp_path: Path) -> None:
    for name, implementation in implementations():
        root = tmp_path / name
        stage, candidate, state, profile_path, driver = setup(root, name)
        assert drive(root, name, stage, candidate, state, profile_path, driver, "execute", "candidate-before").returncode == 97
        _marker, commitment = pending(state)
        assert drive(root, name, stage, candidate, state, profile_path, driver, "recover", "candidate-after").returncode == 97
        assert drive(root, name, stage, candidate, state, profile_path, driver, "recover", "receipt-after").returncode == 97
        result = implementation.recover_pending_commits(
            state,
            candidate,
            json.loads(profile_path.read_text()),
            {"locator": str(profile_path), "sha256": implementation.file_hash(profile_path)},
        )
        assert result[0]["result"] == "PENDING_COMMIT_COMPLETED"
        assert implementation.candidate_state(candidate) == commitment["candidate_after"]


def test_missing_pending_result_restores_predecessor_without_replay(
    tmp_path: Path,
) -> None:
    for name, implementation in implementations():
        root = tmp_path / name
        stage, candidate, state, profile_path, driver = setup(root, name)
        with sqlite3.connect(candidate) as database:
            database.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        before = implementation.candidate_state(candidate)
        assert drive(root, name, stage, candidate, state, profile_path, driver, "execute", "candidate-after").returncode == 97
        marker, value = pending(state)
        work = Path(value["result_directory"])
        shutil.move(work / "receipt.json", root / "preserved-missing-receipt.json")
        result = implementation.recover_pending_commits(
            state,
            candidate,
            json.loads(profile_path.read_text()),
            {"locator": str(profile_path), "sha256": implementation.file_hash(profile_path)},
        )
        assert result[0]["result"] == "PREDECESSOR_RESTORED"
        assert implementation.candidate_state(candidate) == before
        assert not marker.exists()


def test_missing_or_conflicting_predecessor_fails_closed(tmp_path: Path) -> None:
    for name, implementation in implementations():
        for mutation in ("missing", "conflicting"):
            root = tmp_path / f"{name}-{mutation}"
            stage, candidate, state, profile_path, driver = setup(root, name)
            assert drive(root, name, stage, candidate, state, profile_path, driver, "execute", "candidate-after").returncode == 97
            marker, value = pending(state)
            backup = marker.parent / "candidate-prior.db"
            if mutation == "missing":
                shutil.move(backup, root / "preserved-missing-backup.db")
            else:
                backup.chmod(0o600)
                backup.write_bytes(b"conflicting")
            with pytest.raises(implementation.ContractError, match="recovery copy"):
                implementation.recover_pending_commits(
                    state,
                    candidate,
                    json.loads(profile_path.read_text()),
                    {"locator": str(profile_path), "sha256": implementation.file_hash(profile_path)},
                )
            assert implementation.candidate_state(candidate) == value["candidate_after"]
            assert marker.exists()


def test_interrupted_fallback_archive_is_idempotent(tmp_path: Path) -> None:
    for name, implementation in implementations():
        root = tmp_path / name
        stage, candidate, state, profile_path, driver = setup(root, name)
        before = implementation.candidate_state(candidate)
        assert drive(root, name, stage, candidate, state, profile_path, driver, "execute", "candidate-after").returncode == 97
        marker, value = pending(state)
        work = Path(value["result_directory"])
        shutil.move(work / "receipt.json", root / "preserved-missing-receipt.json")
        assert drive(root, name, stage, candidate, state, profile_path, driver, "recover", "fallback-result-after").returncode == 97
        archive = state / "failed-pending-commits" / stage["stage_id"] / value["stage_identity"] / value["content_hash"]
        assert implementation.candidate_state(candidate) == before
        assert (archive / "result").is_dir() and marker.exists()
        result = implementation.recover_pending_commits(
            state,
            candidate,
            json.loads(profile_path.read_text()),
            {"locator": str(profile_path), "sha256": implementation.file_hash(profile_path)},
        )
        assert result == [{"result": "PREDECESSOR_RESTORED", "reason": "pending result or receipt is unavailable"}]
        assert (archive / "control/pending-commit.json").is_file()
        assert not marker.exists()


def test_interrupted_fallback_control_move_remains_retryable(tmp_path: Path) -> None:
    for name, implementation in implementations():
        root = tmp_path / name
        stage, candidate, state, profile_path, driver = setup(root, name)
        before = implementation.candidate_state(candidate)
        assert drive(root, name, stage, candidate, state, profile_path, driver, "execute", "candidate-after").returncode == 97
        marker, value = pending(state)
        work = Path(value["result_directory"])
        shutil.move(work / "receipt.json", root / "preserved-missing-receipt.json")
        assert drive(root, name, stage, candidate, state, profile_path, driver, "recover", "fallback-result-after").returncode == 97
        assert drive(root, name, stage, candidate, state, profile_path, driver, "recover", "fallback-control-after").returncode == 97
        assert implementation.recover_pending_commits(
            state,
            candidate,
            json.loads(profile_path.read_text()),
            {"locator": str(profile_path), "sha256": implementation.file_hash(profile_path)},
        ) == []
        assert implementation.candidate_state(candidate) == before
        retried = implementation.execute_stage(
            stage,
            json.loads(profile_path.read_text()),
            {"locator": str(profile_path), "sha256": implementation.file_hash(profile_path)},
            state,
            candidate,
            {}, {}, {}, {},
        )
        assert retried["status"] == "COMPLETE"
        assert implementation.candidate_state(candidate) == retried["candidate_after"]


def test_pending_recovery_respects_active_writer_lock(tmp_path: Path) -> None:
    for name, implementation in implementations():
        root = tmp_path / name
        stage, candidate, state, profile_path, driver = setup(root, name)
        ready = root / "ready"
        release = root / "release"
        configuration = root / "writer-hold.json"
        configuration.write_text(json.dumps({
            "action": "execute",
            "candidate": str(candidate),
            "fault": "hold-candidate",
            "implementation": name,
            "implementation_path": str(STANDALONE),
            "profile": str(profile_path),
            "ready": str(ready),
            "release": str(release),
            "stage": stage,
            "state": str(state),
        }, sort_keys=True) + "\n")
        process = subprocess.Popen([sys.executable, str(driver), str(configuration)])
        for _ in range(500):
            if ready.exists():
                break
            assert process.poll() is None
            import time
            time.sleep(.02)
        assert ready.exists()
        marker, _value = pending(state)
        with pytest.raises(implementation.ContractError, match="writer lock"):
            implementation.recover_pending_commits(
                state,
                candidate,
                json.loads(profile_path.read_text()),
                {"locator": str(profile_path), "sha256": implementation.file_hash(profile_path)},
            )
        assert marker.exists()
        release.write_text("continue")
        assert process.wait(15) == 0


@pytest.mark.parametrize("boundary", ("record", "archive", "restore", "result", "control"))
@pytest.mark.parametrize("moment", ("before", "after"))
def test_every_fallback_publication_boundary_is_restartable(
    tmp_path: Path, boundary: str, moment: str
) -> None:
    if boundary == "control" and moment == "after":
        return
    for name, implementation in implementations():
        root = tmp_path / f"{name}-{boundary}-{moment}"
        stage, candidate, state, profile_path, driver = setup(root, name)
        before = implementation.candidate_state(candidate)
        assert drive(root, name, stage, candidate, state, profile_path, driver, "execute", "candidate-after").returncode == 97
        marker, value = pending(state)
        work = Path(value["result_directory"])
        shutil.move(work / "receipt.json", root / "preserved-missing-receipt.json")
        fault = f"fallback-{boundary}-{moment}"
        assert drive(
            root, name, stage, candidate, state, profile_path, driver, "recover", fault,
            value["content_hash"],
        ).returncode == 97
        result = implementation.recover_pending_commits(
            state,
            candidate,
            json.loads(profile_path.read_text()),
            {"locator": str(profile_path), "sha256": implementation.file_hash(profile_path)},
        )
        assert result[0]["result"] == "PREDECESSOR_RESTORED"
        assert implementation.candidate_state(candidate) == before
        assert not marker.exists()


def test_fallback_conflicts_reject_before_any_mutation(tmp_path: Path) -> None:
    for name, implementation in implementations():
        for conflict in ("result", "control"):
            for kind in ("directory", "regular-file", "live-symlink", "dangling-symlink"):
                root = tmp_path / f"{name}-{conflict}-{kind}"
                stage, candidate, state, profile_path, driver = setup(root, name)
                assert drive(root, name, stage, candidate, state, profile_path, driver, "execute", "candidate-after").returncode == 97
                marker, value = pending(state)
                work = Path(value["result_directory"])
                shutil.move(work / "receipt.json", root / "preserved-missing-receipt.json")
                archive = state / "failed-pending-commits" / stage["stage_id"] / value["stage_identity"] / value["content_hash"]
                archive.mkdir(parents=True)
                body = {
                    "format_version": implementation.PENDING_COMMIT_FORMAT,
                    "pending_content_hash": value["content_hash"],
                    "result": "PREDECESSOR_RESTORED",
                    "reason": "pending result or receipt is unavailable",
                    "candidate": value["candidate_before"],
                }
                implementation.atomic_json(
                    archive / "recovery.json",
                    {**body, "content_hash": implementation.object_hash(body)},
                )
                archive_entry = archive / conflict
                if kind == "directory":
                    archive_entry.mkdir()
                    (archive_entry / "unrelated-material.txt").write_text("conflict")
                elif kind == "regular-file":
                    archive_entry.write_text("conflict")
                elif kind == "live-symlink":
                    target = root / "link-target"
                    target.mkdir()
                    archive_entry.symlink_to(target, target_is_directory=True)
                else:
                    archive_entry.symlink_to(root / "missing-target", target_is_directory=True)
                authoritative = implementation.candidate_state(candidate)
                work_before = retained_state(work)
                control_before = retained_state(marker.parent)
                archive_before = retained_state(archive)
                for _ in range(2):
                    with pytest.raises(implementation.ContractError, match=f"conflicting {conflict}"):
                        implementation.recover_pending_commits(
                            state,
                            candidate,
                            json.loads(profile_path.read_text()),
                            {"locator": str(profile_path), "sha256": implementation.file_hash(profile_path)},
                        )
                    assert implementation.candidate_state(candidate) == authoritative
                    assert retained_state(work) == work_before
                    assert retained_state(marker.parent) == control_before
                    assert retained_state(archive) == archive_before


def test_r4_incomplete_archive_publication_is_recoverable(tmp_path: Path) -> None:
    for name, implementation in implementations():
        root = tmp_path / name
        stage, candidate, state, profile_path, driver = setup(root, name)
        before = implementation.candidate_state(candidate)
        assert drive(root, name, stage, candidate, state, profile_path, driver, "execute", "candidate-after").returncode == 97
        marker, value = pending(state)
        work = Path(value["result_directory"])
        shutil.move(work / "receipt.json", root / "preserved-missing-receipt.json")
        archive = state / "failed-pending-commits" / stage["stage_id"] / value["stage_identity"] / value["content_hash"]
        archive.mkdir(parents=True)
        (archive / ".recovery.json.interrupted.tmp").write_text("unpublished")
        result = implementation.recover_pending_commits(
            state,
            candidate,
            json.loads(profile_path.read_text()),
            {"locator": str(profile_path), "sha256": implementation.file_hash(profile_path)},
        )
        assert result[0]["result"] == "PREDECESSOR_RESTORED"
        assert implementation.candidate_state(candidate) == before
        assert not marker.exists()
