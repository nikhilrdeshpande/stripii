"""CLI behaviour, exit codes, and the stdout/stderr split that makes pipes work."""

from __future__ import annotations

import json

import pytest

from stripii.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main

from .conftest import (
    FINANCE_STATEMENT,
    HEALTH_REPORT,
    requires_crypto,
    requires_ocr,
)


@pytest.fixture
def report(tmp_path):
    path = tmp_path / "report.txt"
    path.write_text(HEALTH_REPORT)
    return path


@pytest.fixture
def statement(tmp_path):
    path = tmp_path / "statement.txt"
    path.write_text(FINANCE_STATEMENT)
    return path


def test_scrub_writes_the_document_to_stdout_and_the_report_to_stderr(report, capsys):
    assert main(["scrub", str(report), "-p", "health"]) == EXIT_OK
    out, err = capsys.readouterr()
    # stdout is the document, and only the document
    assert "ASSESSMENT" in out
    assert "Margaret Ellen Whitfield" not in out
    assert "replacement(s)" not in out
    # the report goes to stderr so `stripii scrub x | pbcopy` works
    assert "replacement(s)" in err


def test_report_does_not_quote_the_values_it_found(report, capsys):
    main(["scrub", str(report), "-p", "health"])
    _, err = capsys.readouterr()
    assert "412-88-9031" not in err
    assert "Margaret" not in err
    assert "SSN" in err  # the type is reported, the value is not


def test_show_values_opts_in_to_the_details(report, capsys):
    main(["scrub", str(report), "-p", "health", "--show-values", "-o", "/dev/null"])
    _, err = capsys.readouterr()
    assert "412-88-9031" in err


def test_scrub_reads_stdin(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", _FakeStdin("Email: jane@example.com\n"))
    assert main(["scrub", "-", "-q"]) == EXIT_OK
    out, _ = capsys.readouterr()
    assert "jane@example.com" not in out
    assert "[[EMAIL_1]]" in out


class _FakeStdin:
    def __init__(self, text):
        self._text = text

    def read(self):
        return self._text


def test_scrub_to_an_output_file(report, tmp_path, capsys):
    destination = tmp_path / "safe.txt"
    assert main(["scrub", str(report), "-p", "health", "-o", str(destination)]) == EXIT_OK
    assert "Margaret Ellen Whitfield" not in destination.read_text()
    assert "Hemoglobin" in destination.read_text()
    out, _ = capsys.readouterr()
    assert out == ""  # nothing on stdout when writing to a file


def test_scrub_in_place(report):
    assert main(["scrub", str(report), "-p", "health", "-i", "-q"]) == EXIT_OK
    assert "Margaret Ellen Whitfield" not in report.read_text()


def test_scan_exits_one_when_it_finds_something(report, capsys):
    assert main(["scan", str(report), "-p", "health"]) == EXIT_FINDINGS
    out, _ = capsys.readouterr()
    assert "replacement(s)" in out


def test_scan_exits_zero_on_a_clean_file(tmp_path, capsys):
    path = tmp_path / "clean.txt"
    path.write_text("The quick brown fox jumped over the lazy dog.\n")
    assert main(["scan", str(path)]) == EXIT_OK


def test_scan_does_not_write_any_output_file(report, tmp_path):
    before = sorted(p.name for p in tmp_path.iterdir())
    main(["scan", str(report)])
    assert sorted(p.name for p in tmp_path.iterdir()) == before


def test_fail_on_secret(tmp_path, capsys):
    path = tmp_path / "config.env"
    path.write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
    assert main(["scrub", str(path), "--fail-on-secret", "-q"]) == EXIT_FINDINGS


def test_fail_on_secret_ignores_ordinary_pii(tmp_path):
    path = tmp_path / "note.txt"
    path.write_text("Email: jane@example.com\n")
    assert main(["scrub", str(path), "--fail-on-secret", "-q"]) == EXIT_OK


def test_fail_on_findings(report):
    assert main(["scrub", str(report), "--fail-on-findings", "-q"]) == EXIT_FINDINGS


def test_json_report_is_parseable(report, capsys):
    main(["scan", str(report), "-p", "health", "--json"])
    out, _ = capsys.readouterr()
    payload = json.loads(out[out.index("["):])
    assert payload[0]["total"] > 0
    assert "PERSON" in payload[0]["counts"]
    # values stay out of the JSON too, unless asked for
    assert "value" not in payload[0]["replacements"][0]


def test_vault_round_trip_through_the_cli(statement, tmp_path, capsys):
    safe = tmp_path / "safe.txt"
    vault = tmp_path / "v.json"
    assert main(["scrub", str(statement), "-p", "finance", "-o", str(safe),
                 "--vault", str(vault), "--plaintext-vault", "-q"]) == EXIT_OK
    assert vault.exists()

    reply = tmp_path / "reply.txt"
    reply.write_text("Summary for [[PERSON_1]] at [[EMAIL_1]].\n")
    assert main(["restore", str(reply), "--vault", str(vault)]) == EXIT_OK
    out, _ = capsys.readouterr()
    assert "Michael J. Rodriguez" in out
    assert "mrodriguez@example.net" in out


def test_no_vault_is_written_unless_asked(report, tmp_path):
    main(["scrub", str(report), "-o", str(tmp_path / "safe.txt"), "-q"])
    assert not list(tmp_path.glob("*.vault"))
    assert sorted(p.name for p in tmp_path.iterdir()) == ["report.txt", "safe.txt"]


@requires_crypto
def test_passphrase_from_the_environment(statement, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SP_PASS", "hunter2-is-not-enough")
    vault = tmp_path / "v.enc"
    assert main(["scrub", str(statement), "-o", str(tmp_path / "s.txt"),
                 "--vault", str(vault), "--passphrase-env", "SP_PASS", "-q"]) == EXIT_OK
    assert b"Rodriguez" not in vault.read_bytes()

    reply = tmp_path / "reply.txt"
    reply.write_text("[[PERSON_1]]\n")
    assert main(["restore", str(reply), "--vault", str(vault),
                 "--passphrase-env", "SP_PASS"]) == EXIT_OK
    out, _ = capsys.readouterr()
    assert "Michael J. Rodriguez" in out


def test_unset_passphrase_variable_is_an_error(statement, tmp_path, capsys):
    assert main(["scrub", str(statement), "--vault", str(tmp_path / "v"),
                 "--passphrase-env", "NOT_SET_ANYWHERE", "-q"]) == EXIT_ERROR
    _, err = capsys.readouterr()
    assert "NOT_SET_ANYWHERE" in err


# --------------------------------------------------------------------------
# overrides and errors
# --------------------------------------------------------------------------

def test_set_overrides_a_single_entity(report, capsys):
    main(["scrub", str(report), "-p", "health", "--set", "DATE=keep", "-q"])
    out, _ = capsys.readouterr()
    assert "03/14/1934" in out


def test_disable_turns_an_entity_off(report, capsys):
    main(["scrub", str(report), "-p", "health", "--disable", "CITY", "-q"])
    out, _ = capsys.readouterr()
    assert "Springfield" in out


def test_unknown_entity_in_set_is_rejected(report, capsys):
    assert main(["scrub", str(report), "--set", "NONSENSE=redact"]) == EXIT_ERROR
    _, err = capsys.readouterr()
    assert "NONSENSE" in err


def test_unknown_action_in_set_is_rejected(report, capsys):
    assert main(["scrub", str(report), "--set", "EMAIL=obliterate"]) == EXIT_ERROR
    _, err = capsys.readouterr()
    assert "obliterate" in err


def test_malformed_set_is_rejected(report, capsys):
    assert main(["scrub", str(report), "--set", "EMAIL"]) == EXIT_ERROR


def test_missing_file_is_reported(capsys):
    assert main(["scrub", "/nonexistent/path.txt"]) == EXIT_ERROR
    _, err = capsys.readouterr()
    assert "no such file" in err


def test_custom_placeholder_template(report, capsys):
    main(["scrub", str(report), "-p", "health", "--placeholder", "<{entity}-{n}>", "-q"])
    out, _ = capsys.readouterr()
    assert "<PERSON-1>" in out


def test_multiple_files_need_a_directory_output(report, statement, tmp_path, capsys):
    assert main(["scrub", str(report), str(statement),
                 "-o", str(tmp_path / "one.txt")]) == EXIT_ERROR
    _, err = capsys.readouterr()
    assert "directory" in err


def test_multiple_files_into_a_directory(report, statement, tmp_path):
    outdir = tmp_path / "out"
    outdir.mkdir()
    assert main(["scrub", str(report), str(statement), "-o", str(outdir), "-q"]) == EXIT_OK
    assert sorted(p.name for p in outdir.iterdir()) == ["report.txt", "statement.txt"]


def test_json_and_csv_inputs_keep_their_structure(tmp_path, capsys):
    path = tmp_path / "people.csv"
    path.write_text("name,email\nJane Smith,jane@example.com\n")
    main(["scrub", str(path), "-q"])
    out, _ = capsys.readouterr()
    assert out.splitlines()[0] == "name,email"
    assert "jane@example.com" not in out


def test_profiles_command_lists_every_profile(capsys):
    assert main(["profiles"]) == EXIT_OK
    out, _ = capsys.readouterr()
    for name in ("default", "health", "finance", "paranoid", "secrets"):
        assert name in out


def test_entities_command_is_machine_readable(capsys):
    assert main(["entities", "--json"]) == EXIT_OK
    out, _ = capsys.readouterr()
    entities = json.loads(out)
    assert "PERSON" in entities
    assert "SSN" in entities


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0


def test_scan_quiet_reports_only_through_the_exit_status(report, capsys):
    assert main(["scan", str(report), "-p", "health", "-q"]) == EXIT_FINDINGS
    out, err = capsys.readouterr()
    assert out == ""
    assert err == ""


def test_scan_quiet_on_a_clean_file(tmp_path, capsys):
    path = tmp_path / "clean.txt"
    path.write_text("The quick brown fox.\n")
    assert main(["scan", str(path), "-q"]) == EXIT_OK
    out, _ = capsys.readouterr()
    assert out == ""


def test_module_entry_point_matches_the_console_script():
    """`python -m stripii` must behave the same as the installed command."""
    import subprocess
    import sys

    completed = subprocess.run(
        [sys.executable, "-m", "stripii", "--version"],
        capture_output=True, text=True, check=False,
    )
    assert completed.returncode == 0
    assert "stripii" in completed.stdout


def test_entities_marks_the_ner_only_ones(capsys):
    assert main(["entities"]) == EXIT_OK
    out, _ = capsys.readouterr()
    lines = {line.split("  ")[0]: line for line in out.splitlines()}
    assert "requires --ner" in lines["LOCATION"]
    assert "requires --ner" not in lines["SSN"]


def test_ner_only_entities_can_still_be_overridden(report):
    """--set must accept an entity the NER backend produces, not just the regexes."""
    assert main(["scrub", str(report), "--set", "ORGANIZATION=redact", "-q"]) == EXIT_OK


def test_format_override_gives_piped_input_structural_handling(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", _FakeStdin('{"routing_number": "021000021"}'))
    assert main(["scrub", "-", "-p", "finance", "-q", "--format", "json"]) == EXIT_OK
    out, _ = capsys.readouterr()
    assert "021000021" not in out
    assert '"routing_number"' in out  # the key survives


def test_format_override_on_a_file_beats_the_extension(tmp_path, capsys):
    path = tmp_path / "data.txt"  # wrong extension on purpose
    path.write_text("name,routing_number\nJane Smith,021000021\n")
    assert main(["scrub", str(path), "-p", "finance", "-q", "--format", "csv"]) == EXIT_OK
    out, _ = capsys.readouterr()
    assert out.splitlines()[0] == "name,routing_number"
    assert "021000021" not in out


def test_structured_scrub_finds_what_flat_text_would_miss(tmp_path, capsys):
    path = tmp_path / "accounts.csv"
    path.write_text("holder,account_number\nJane Smith,483920175\n")
    main(["scrub", str(path), "-p", "finance", "-q"])
    out, _ = capsys.readouterr()
    assert "483920175" not in out


# --------------------------------------------------------------------------
# OCR
# --------------------------------------------------------------------------

@requires_ocr
@pytest.mark.slow
def test_ocr_flag_reads_a_scanned_pdf(tmp_path, capsys):
    from .conftest import write_scanned_pdf

    path = tmp_path / "scan.pdf"
    write_scanned_pdf(path)

    # without --ocr it must refuse rather than emit an empty document
    assert main(["scan", str(path), "-p", "health", "-q"]) == EXIT_ERROR

    assert main(["scrub", str(path), "-p", "health", "--ocr", "-q"]) == EXIT_OK
    out, _ = capsys.readouterr()
    assert "Margaret Whitfield" not in out
    assert "Hemoglobin 10.2 g/dL" in out


@requires_ocr
@pytest.mark.slow
def test_ocr_writes_a_redacted_pdf(tmp_path, capsys):
    from stripii.ocr import read_document

    from .conftest import write_scanned_pdf

    source = tmp_path / "scan.pdf"
    write_scanned_pdf(source)
    out_pdf = tmp_path / "redacted.pdf"

    assert main(["scrub", str(source), "-p", "health", "--ocr",
                 "-o", str(out_pdf), "-q"]) == EXIT_OK
    assert out_pdf.exists()

    recovered = read_document(out_pdf).text
    assert "Margaret Whitfield" not in recovered
    assert "412-88-9031" not in recovered


def test_an_image_without_ocr_says_to_use_ocr(tmp_path, capsys):
    path = tmp_path / "photo.png"
    path.write_bytes(b"\x89PNG\r\n\x1a\n")
    assert main(["scrub", str(path), "-p", "health"]) == EXIT_ERROR
    _, err = capsys.readouterr()
    assert "--ocr" in err


# --------------------------------------------------------------------------
# vault passphrases
# --------------------------------------------------------------------------

def test_an_unencrypted_vault_needs_saying_so(statement, tmp_path, capsys):
    vault = tmp_path / "v.json"
    assert main(["scrub", str(statement), "-o", str(tmp_path / "s.txt"),
                 "--vault", str(vault), "-q"]) == EXIT_ERROR
    assert not vault.exists()
    assert "--plaintext-vault" in capsys.readouterr().err


@requires_crypto
@pytest.mark.parametrize("passphrase", ["", "seven77"])
def test_an_empty_or_short_prompted_passphrase_is_refused(statement, tmp_path, capsys,
                                                          monkeypatch, passphrase):
    monkeypatch.setattr("stripii.cli.getpass", lambda prompt="": passphrase)
    vault = tmp_path / "v.enc"
    assert main(["scrub", str(statement), "-o", str(tmp_path / "s.txt"),
                 "--vault", str(vault), "--passphrase", "-q"]) == EXIT_ERROR
    assert not vault.exists()


@requires_crypto
def test_a_new_passphrase_is_asked_for_twice(statement, tmp_path, capsys, monkeypatch):
    answers = iter(["a long passphrase", "a long passphrase, mistyped"])
    monkeypatch.setattr("stripii.cli.getpass", lambda prompt="": next(answers))
    vault = tmp_path / "v.enc"
    assert main(["scrub", str(statement), "-o", str(tmp_path / "s.txt"),
                 "--vault", str(vault), "--passphrase", "-q"]) == EXIT_ERROR
    assert "do not match" in capsys.readouterr().err
    assert not vault.exists()

    answers = iter(["a long passphrase", "a long passphrase", "a long passphrase"])
    assert main(["scrub", str(statement), "-o", str(tmp_path / "s.txt"),
                 "--vault", str(vault), "--passphrase", "-q"]) == EXIT_OK
    assert b"Rodriguez" not in vault.read_bytes()
    reply = tmp_path / "reply.txt"
    reply.write_text("[[PERSON_1]]\n")
    # restoring asks once
    assert main(["restore", str(reply), "--vault", str(vault), "--passphrase"]) == EXIT_OK
    assert "Rodriguez" in capsys.readouterr().out


def test_the_key_env_secret_is_stretched_not_hashed_once(monkeypatch):
    import argparse
    import hashlib

    from stripii.cli import resolve_keys

    monkeypatch.setenv("SP_KEY", "a random secret")
    key = resolve_keys(argparse.Namespace(key_env="SP_KEY"))
    assert len(key) == 32
    assert key != hashlib.sha256(b"a random secret").digest()
    assert key == resolve_keys(argparse.Namespace(key_env="SP_KEY"))   # stable across runs


@pytest.mark.parametrize("dpi", ["0", "71", "601", "5000"])
def test_an_absurd_ocr_dpi_is_refused(report, dpi, capsys):
    with pytest.raises(SystemExit):
        main(["scrub", str(report), "--ocr-dpi", dpi])
    assert "between 72 and 600" in capsys.readouterr().err
