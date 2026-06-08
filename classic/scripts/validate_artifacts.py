#!/usr/bin/env python3
"""Validate Atomic Rain eval and artifact contract files.

This intentionally avoids third-party jsonschema dependencies. It performs
contract-level checks that are stable for skill packaging: schema files must be
present and coherent, behavior evals must stay usable, and optional JSON/JSONL
artifacts can be checked against the subset of JSON Schema used here.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

SCHEMA_FILES = {
    "evidence": ROOT / "schemas" / "evidence.schema.json",
    "vulnerability": ROOT / "schemas" / "vulnerability.schema.json",
    "report": ROOT / "schemas" / "report.schema.json",
}

SCHEMA_REQUIRED_FIELDS = {
    "evidence": {"schema_version", "evidence_id", "collected_at", "profile", "target", "evidence_type", "source", "artifacts"},
    "vulnerability": {"schema_version", "vuln_id", "status", "title", "vuln_type", "severity", "confidence", "target", "affected_asset", "dedupe_key", "evidence_refs", "false_positive_checks"},
    "report": {"schema_version", "report_id", "generated_at", "profile", "target", "summary", "findings", "quality_gates"},
}

DEDUPE_PARTS = ("vuln_type", "normalized_asset", "endpoint", "parameter", "auth_context", "root_cause")
HIGH_IMPACT_SEVERITIES = {"High", "Critical"}
NON_NOTE_EVIDENCE_TYPES = {"http", "screenshot", "console", "traffic-flow", "static-analysis", "oob"}
DEGRADED_RE = re.compile(r"^DEGRADED:[A-Z0-9_]+$")
REQUIRED_EVAL_COVERAGE = {
    "dynamic_loading": ("read", "route"),
    "variant_boundary": ("classic", "toolplus", "mcp"),
    "degraded_mode": ("DEGRADED:",),
    "artifact_quality": ("artifact-quality-gates", "report-template", "schema"),
    "business_logic_routing": ("business-flow", "resource", "sensitivity"),
    "hitl_oob": ("P3.5", "OOB", "public"),
}


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def display_path(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def type_matches(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return (isinstance(value, (int, float)) and not isinstance(value, bool))
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    return True


def validate_value(value: Any, schema: dict[str, Any], path: str, errors: list[str]) -> None:
    expected_type = schema.get("type")
    if isinstance(expected_type, list):
        if not any(type_matches(value, item) for item in expected_type):
            errors.append(f"{path}: expected one of {expected_type}, got {type(value).__name__}")
            return
    elif isinstance(expected_type, str) and not type_matches(value, expected_type):
        errors.append(f"{path}: expected {expected_type}, got {type(value).__name__}")
        return

    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: value {value!r} not in enum {schema['enum']}")
    if isinstance(value, str):
        min_length = schema.get("minLength")
        if isinstance(min_length, int) and len(value) < min_length:
            errors.append(f"{path}: string shorter than minLength={min_length}")
    if "pattern" in schema and isinstance(value, str):
        if not re.match(schema["pattern"], value):
            errors.append(f"{path}: value {value!r} does not match pattern {schema['pattern']!r}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: number below minimum={schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: number above maximum={schema['maximum']}")
    if isinstance(value, list):
        min_items = schema.get("minItems")
        if isinstance(min_items, int) and len(value) < min_items:
            errors.append(f"{path}: array shorter than minItems={min_items}")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for idx, item in enumerate(value):
                validate_value(item, item_schema, f"{path}[{idx}]", errors)
    if isinstance(value, dict):
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                errors.append(f"{path}: missing required key {key!r}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            extra = sorted(set(value) - set(properties))
            if extra:
                errors.append(f"{path}: unexpected keys {extra}")
        for key, sub_schema in properties.items():
            if key in value and isinstance(sub_schema, dict) and "$ref" not in sub_schema:
                validate_value(value[key], sub_schema, f"{path}.{key}", errors)


def check_schemas(errors: list[str]) -> dict[str, dict[str, Any]]:
    schemas: dict[str, dict[str, Any]] = {}
    for name, path in SCHEMA_FILES.items():
        if not path.exists():
            errors.append(f"missing schema: {path.relative_to(ROOT).as_posix()}")
            continue
        data = load_json(path)
        schemas[name] = data
        if data.get("type") != "object":
            errors.append(f"{path.name}: root type must be object")
        if "properties" not in data or not isinstance(data["properties"], dict):
            errors.append(f"{path.name}: missing properties object")
        declared_required = set(data.get("required", []))
        missing = SCHEMA_REQUIRED_FIELDS[name] - declared_required
        if missing:
            errors.append(f"{path.name}: required list missing {sorted(missing)}")
        for field in SCHEMA_REQUIRED_FIELDS[name]:
            if field not in data.get("properties", {}):
                errors.append(f"{path.name}: properties missing required field {field}")
    return schemas


def check_evals(errors: list[str]) -> None:
    path = ROOT / "evals" / "evals.json"
    if not path.exists():
        errors.append("missing behavior eval set: evals/evals.json")
        return
    data = load_json(path)
    if data.get("skill_name") != "atomic-rain":
        errors.append("evals/evals.json: skill_name must be atomic-rain")
    evals = data.get("evals")
    if not isinstance(evals, list) or len(evals) < 8:
        errors.append("evals/evals.json: expected at least 8 eval cases")
        return
    seen: set[str] = set()
    profile_coverage: set[str] = set()
    coverage_seen: set[str] = set()
    coverage_assertions: dict[str, list[str]] = {tag: [] for tag in REQUIRED_EVAL_COVERAGE}
    for idx, item in enumerate(evals):
        if not isinstance(item, dict):
            errors.append(f"evals[{idx}]: must be an object")
            continue
        eval_id = item.get("id")
        if not isinstance(eval_id, str) or not eval_id:
            errors.append(f"evals[{idx}]: missing string id")
        elif eval_id in seen:
            errors.append(f"evals[{idx}]: duplicate id {eval_id}")
        else:
            seen.add(eval_id)
        for key in ("prompt", "expected_output"):
            if not isinstance(item.get(key), str) or len(item[key]) < 40:
                errors.append(f"evals[{idx}]: {key} must be a descriptive string")
        profiles = item.get("profiles")
        if not isinstance(profiles, list) or not profiles:
            errors.append(f"evals[{idx}]: profiles must be a non-empty list")
        else:
            profile_coverage.update(str(p) for p in profiles)
        coverage = item.get("coverage")
        if not isinstance(coverage, list) or not coverage:
            errors.append(f"evals[{idx}]: coverage must be a non-empty list")
            coverage = []
        else:
            for tag in coverage:
                if not isinstance(tag, str) or tag not in REQUIRED_EVAL_COVERAGE:
                    errors.append(f"evals[{idx}]: unknown coverage tag {tag!r}")
                else:
                    coverage_seen.add(tag)
        assertions = item.get("assertions")
        if not isinstance(assertions, list) or len(assertions) < 2:
            errors.append(f"evals[{idx}]: expected at least 2 assertions")
        else:
            assertion_text = " ".join(str(assertion.get("text", "")) for assertion in assertions)
            for a_idx, assertion in enumerate(assertions):
                if not isinstance(assertion, dict) or not isinstance(assertion.get("text"), str):
                    errors.append(f"evals[{idx}].assertions[{a_idx}]: missing text")
                if assertion.get("must_pass") is not True:
                    errors.append(f"evals[{idx}].assertions[{a_idx}]: must_pass should be true for gate assertions")
            for tag in coverage:
                if tag in REQUIRED_EVAL_COVERAGE:
                    coverage_assertions[tag].append(assertion_text.lower())
    for required_profile in ("classic", "toolplus"):
        if required_profile not in profile_coverage:
            errors.append(f"evals/evals.json: missing profile coverage for {required_profile}")
    for required_coverage in sorted(REQUIRED_EVAL_COVERAGE):
        if required_coverage not in coverage_seen:
            errors.append(f"evals/evals.json: missing coverage tag {required_coverage}")
        else:
            joined = " ".join(coverage_assertions[required_coverage])
            missing_terms = [term for term in REQUIRED_EVAL_COVERAGE[required_coverage] if term.lower() not in joined]
            if missing_terms:
                errors.append(f"evals/evals.json: coverage {required_coverage} assertions missing terms {missing_terms}")


def classify_artifact(path: Path) -> str | None:
    name = path.name.lower()
    if "evidence" in name:
        return "evidence"
    if "vulnerability" in name or "vuln" in name:
        return "vulnerability"
    if "report" in name:
        return "report"
    return None


def load_capability_ids() -> dict[str, set[str]]:
    result: dict[str, set[str]] = {"classic": set(), "toolplus": set(), "deployed-mixed": set()}
    for profile, filename in (("classic", "cli-capabilities.json"), ("toolplus", "mcp-capabilities.json")):
        path = ROOT / "capabilities" / filename
        if not path.exists():
            continue
        data = load_json(path)
        ids = {item.get("id") for item in data.get("capabilities", []) if isinstance(item, dict) and isinstance(item.get("id"), str)}
        result[profile] = ids
        result["deployed-mixed"].update(ids)
    return result


def read_artifact_records(artifact_dir: Path, errors: list[str]) -> dict[str, list[tuple[Path, int, dict[str, Any]]]]:
    records: dict[str, list[tuple[Path, int, dict[str, Any]]]] = {"evidence": [], "vulnerability": [], "report": []}
    if not artifact_dir.exists():
        return records
    for path in sorted(p for p in artifact_dir.rglob("*") if p.is_file() and p.suffix.lower() in {".json", ".jsonl"}):
        kind = classify_artifact(path)
        if kind is None:
            continue
        raw_records: list[Any] = []
        if path.suffix.lower() == ".jsonl":
            for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if not line.strip():
                    continue
                try:
                    raw_records.append(json.loads(line))
                except json.JSONDecodeError as exc:
                        errors.append(f"{display_path(path)}:{line_no}: invalid JSONL: {exc}")
        else:
            raw_records.append(load_json(path))
        for idx, record in enumerate(raw_records):
            if isinstance(record, dict):
                records[kind].append((path, idx, record))
            else:
                errors.append(f"{path.relative_to(ROOT).as_posix()}[{idx}]: artifact record must be object")
    return records


def check_dedupe_key(value: str, location: str, errors: list[str]) -> None:
    parts = value.split("|")
    if len(parts) != len(DEDUPE_PARTS):
        errors.append(f"{location}: dedupe_key must have {len(DEDUPE_PARTS)} pipe-separated parts: {'|'.join(DEDUPE_PARTS)}")
        return
    for name, part in zip(DEDUPE_PARTS, parts):
        if not part:
            errors.append(f"{location}: dedupe_key part {name} is empty")
        if part != part.strip():
            errors.append(f"{location}: dedupe_key part {name} has surrounding whitespace")
        if part != part.lower():
            errors.append(f"{location}: dedupe_key part {name} should be lowercase/normalized")


def has_first_pass_signal(vuln: dict[str, Any]) -> bool:
    signal = vuln.get("first_pass_signal")
    if not isinstance(signal, dict):
        return False
    return any(signal.get(key) not in (None, "", []) for key in ("status_code", "body_length_delta", "duration_ms", "marker"))


def all_fp_checks_passed(vuln: dict[str, Any]) -> bool:
    checks = vuln.get("false_positive_checks")
    return isinstance(checks, list) and bool(checks) and all(isinstance(item, dict) and item.get("passed") is True for item in checks)


def artifact_location(path: Path, idx: int) -> str:
    return f"{display_path(path)}[{idx}]"


def check_quality_gates(records: dict[str, list[tuple[Path, int, dict[str, Any]]]], errors: list[str]) -> None:
    capability_ids = load_capability_ids()
    evidence_by_id: dict[str, dict[str, Any]] = {}
    vulnerability_by_id: dict[str, dict[str, Any]] = {}
    dedupe_to_vuln: dict[str, str] = {}

    for path, idx, evidence in records["evidence"]:
        location = artifact_location(path, idx)
        evidence_id = evidence.get("evidence_id")
        if isinstance(evidence_id, str):
            if evidence_id in evidence_by_id:
                errors.append(f"{location}: duplicate evidence_id {evidence_id}")
            evidence_by_id[evidence_id] = evidence
        markers = evidence.get("degraded_markers", [])
        for marker in markers if isinstance(markers, list) else []:
            if not isinstance(marker, str) or not DEGRADED_RE.match(marker):
                errors.append(f"{location}: invalid degraded marker {marker!r}")
        profile = evidence.get("profile")
        capability = evidence.get("source", {}).get("capability") if isinstance(evidence.get("source"), dict) else None
        if isinstance(profile, str) and isinstance(capability, str):
            allowed = capability_ids.get(profile, set())
            if allowed and capability not in allowed:
                errors.append(f"{location}: source.capability {capability!r} is not registered for profile {profile}")

    for path, idx, vuln in records["vulnerability"]:
        location = artifact_location(path, idx)
        vuln_id = vuln.get("vuln_id")
        if isinstance(vuln_id, str):
            if vuln_id in vulnerability_by_id:
                errors.append(f"{location}: duplicate vuln_id {vuln_id}")
            vulnerability_by_id[vuln_id] = vuln

        dedupe_key = vuln.get("dedupe_key")
        if isinstance(dedupe_key, str):
            check_dedupe_key(dedupe_key, location, errors)
            if vuln.get("status") != "rejected":
                prior = dedupe_to_vuln.get(dedupe_key)
                if prior and prior != vuln_id:
                    errors.append(f"{location}: duplicate non-rejected dedupe_key {dedupe_key!r} also used by {prior}")
                elif isinstance(vuln_id, str):
                    dedupe_to_vuln[dedupe_key] = vuln_id

        refs = vuln.get("evidence_refs", [])
        if isinstance(refs, list):
            for ref in refs:
                if ref not in evidence_by_id:
                    errors.append(f"{location}: evidence_ref {ref!r} does not resolve to an evidence artifact")

        status = vuln.get("status")
        severity = vuln.get("severity")
        confidence = vuln.get("confidence")
        if status == "confirmed":
            if not has_first_pass_signal(vuln):
                errors.append(f"{location}: confirmed finding requires first_pass_signal with concrete signal")
            if not all_fp_checks_passed(vuln):
                errors.append(f"{location}: confirmed finding requires all false_positive_checks passed")
            if not isinstance(confidence, (int, float)) or confidence < 0.70:
                errors.append(f"{location}: confirmed finding requires confidence >= 0.70")
        if status == "confirmed" and severity in HIGH_IMPACT_SEVERITIES:
            if not isinstance(confidence, (int, float)) or confidence < 0.80:
                errors.append(f"{location}: {severity} confirmed finding requires confidence >= 0.80")
            if not vuln.get("cvss_vector"):
                errors.append(f"{location}: {severity} confirmed finding requires cvss_vector")
            if not vuln.get("cwe"):
                errors.append(f"{location}: {severity} confirmed finding requires cwe")
            ref_types = {evidence_by_id.get(ref, {}).get("evidence_type") for ref in refs if isinstance(ref, str)}
            if not (ref_types & NON_NOTE_EVIDENCE_TYPES):
                errors.append(f"{location}: {severity} confirmed finding requires at least one non-note evidence artifact")

        if status == "blocked" and not vuln.get("blocked_reason"):
            errors.append(f"{location}: blocked finding requires blocked_reason")
        if status != "blocked" and vuln.get("blocked_reason"):
            errors.append(f"{location}: blocked_reason should only be present when status is blocked")

        vuln_markers = set(vuln.get("degraded_markers", []) if isinstance(vuln.get("degraded_markers"), list) else [])
        evidence_markers: set[str] = set()
        for ref in refs if isinstance(refs, list) else []:
            ref_evidence = evidence_by_id.get(ref)
            if isinstance(ref_evidence, dict):
                evidence_markers.update(ref_evidence.get("degraded_markers", []) if isinstance(ref_evidence.get("degraded_markers"), list) else [])
        missing_markers = sorted(evidence_markers - vuln_markers)
        if missing_markers:
            errors.append(f"{location}: vulnerability degraded_markers missing referenced evidence markers {missing_markers}")

    for path, idx, report in records["report"]:
        location = artifact_location(path, idx)
        findings = report.get("findings", [])
        if not isinstance(findings, list):
            continue
        confirmed_count = sum(1 for item in findings if isinstance(item, dict) and item.get("status") == "confirmed")
        blocked_count = sum(1 for item in findings if isinstance(item, dict) and item.get("status") == "blocked")
        summary = report.get("summary", {}) if isinstance(report.get("summary"), dict) else {}
        if summary.get("confirmed_count") != confirmed_count:
            errors.append(f"{location}: summary.confirmed_count={summary.get('confirmed_count')} but findings contain {confirmed_count}")
        if summary.get("blocked_count") != blocked_count:
            errors.append(f"{location}: summary.blocked_count={summary.get('blocked_count')} but findings contain {blocked_count}")

        quality = report.get("quality_gates", {}) if isinstance(report.get("quality_gates"), dict) else {}
        dedupe_keys: list[str] = []
        report_has_degraded = False
        high_critical_non_note_ok = True
        for f_idx, finding in enumerate(findings):
            if not isinstance(finding, dict):
                continue
            finding_loc = f"{location}.findings[{f_idx}]"
            refs = finding.get("evidence_refs", [])
            for ref in refs if isinstance(refs, list) else []:
                if ref not in evidence_by_id:
                    errors.append(f"{finding_loc}: evidence_ref {ref!r} does not resolve to an evidence artifact")
            dedupe_key = finding.get("dedupe_key")
            if isinstance(dedupe_key, str):
                check_dedupe_key(dedupe_key, finding_loc, errors)
                dedupe_keys.append(dedupe_key)
            vuln = vulnerability_by_id.get(finding.get("vuln_id"))
            if vuln:
                if finding.get("dedupe_key") != vuln.get("dedupe_key"):
                    errors.append(f"{finding_loc}: dedupe_key does not match vulnerability record")
                if vuln.get("degraded_markers"):
                    report_has_degraded = True
            if finding.get("status") == "confirmed" and finding.get("severity") in HIGH_IMPACT_SEVERITIES:
                ref_types = {evidence_by_id.get(ref, {}).get("evidence_type") for ref in refs if isinstance(ref, str)}
                if not (ref_types & NON_NOTE_EVIDENCE_TYPES):
                    high_critical_non_note_ok = False

        if len(dedupe_keys) != len(set(dedupe_keys)):
            errors.append(f"{location}: report findings contain duplicate dedupe_key values")
        expected_quality = {
            "dedupe_keys_unique": len(dedupe_keys) == len(set(dedupe_keys)),
            "high_critical_have_non_note_evidence": high_critical_non_note_ok,
        }
        for key, expected in expected_quality.items():
            if quality.get(key) is not expected:
                errors.append(f"{location}: quality_gates.{key} should be {expected}")
        if confirmed_count > 0:
            for key in ("first_pass_signals_present", "false_positive_checks_present", "evidence_refs_present", "p3_5_external_resources_respected"):
                if quality.get(key) is not True:
                    errors.append(f"{location}: confirmed report requires quality_gates.{key}=true")
        if report_has_degraded and quality.get("degraded_markers_declared") is not True:
            errors.append(f"{location}: degraded findings require quality_gates.degraded_markers_declared=true")


def check_artifact_dir(artifact_dir: Path, schemas: dict[str, dict[str, Any]], errors: list[str]) -> None:
    records = read_artifact_records(artifact_dir, errors)
    for kind, entries in records.items():
        if kind not in schemas:
            continue
        for path, idx, record in entries:
            validate_value(record, schemas[kind], f"{display_path(path)}[{idx}]", errors)
    check_quality_gates(records, errors)


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Atomic Rain evals, schemas, and optional artifacts.")
    parser.add_argument("--artifact-dir", type=Path, default=ROOT / "artifacts", help="Optional artifact directory to validate if present")
    args = parser.parse_args()

    errors: list[str] = []
    schemas = check_schemas(errors)
    check_evals(errors)
    check_artifact_dir(args.artifact_dir.resolve(), schemas, errors)

    if errors:
        print("[artifacts] FAIL")
        for error in errors:
            print(f"  - {error}")
        return 1
    print(f"[artifacts] OK schemas={len(schemas)} evals={(ROOT / 'evals' / 'evals.json').exists()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
