#!/usr/bin/env python3
"""Schema conformance gate for the frozen normative JSON Schemas.

The schemas in ../schemas are the normative declaration of the verifier's input
and output shapes (README §"Authority of schemas"). This gate keeps them honest
WITHOUT importing any verifier (repo doctrine: conformance is data-only):

  1. every schema is valid JSON Schema Draft 2020-12,
  2. every fixture `input.json` validates against schemas/input/verifier-request,
  3. every positive fixture's base certificate validates against
     schemas/input/base-certificate, and every CCSP/1 envelope fixture whose
     defect is a shape the schema expresses fails it,
  4. every positive fixture's settlement material validates against
     schemas/input/settlement-material, and every adversarial fixture whose
     material defect is a shape the schema expresses fails it,
  5. every positive fixture's verification package validates against
     schemas/input/verification-package, and every package fixture whose defect
     is a shape the schema expresses fails it.

The OUTPUT schema (schemas/output/verifier-result) describes the FULL VerifierResult
a verifier emits — a different object from each fixture's minimal
`expected-result.json` comparison view — so it is validated against a real
verifier's output in the verifier-toolkit test suite, not here (that would couple
this data-only repo to a verifier implementation). See README.

Run:  PYTHONPATH=. python validate_schemas.py [--fixtures DIR] [--schemas DIR]
"""
import argparse
import glob
import json
import os
import sys

import jsonschema

# C-series fixtures whose envelope defect is a shape: the certificate schema
# itself refuses them. The other C-series defects (a digest or commitment that
# does not recompute, a domain not under evaluation, a repeated member name) are
# beyond what a schema over a parsed value can express, and are decided by the
# verifier; see the schema's `$comment`.
SCHEMA_REJECTED_CERTIFICATES = [
    "C002", "C003", "C004", "C005", "C006", "C007", "C008", "C009",
    "C010", "C011", "C012", "C016",
]

# Adversarial fixtures whose settlement-material defect is a shape: a member
# absent (V005 bridges, V023 finality proof, V024 assignment, V045 manifest), a
# constant broken (V004 profile, V050/V058 action_ordinal), a quantity that is not
# `<integer>.<2 digits> CERT` (V060, V062) or an empty ledger hash (V063). The
# other material defects are values the verifier decides; see the schema's
# `$comment`.
SCHEMA_REJECTED_MATERIALS = [
    "V004", "V005", "V023", "V024", "V045", "V050", "V058", "V060", "V062", "V063",
]

# Package fixtures whose defect is a shape: a member outside the closed set (V069)
# or a required member absent (V070). The other package defects (a declaration
# that contradicts the artifacts, a substituted certificate) are values the
# verifier decides; see the schema's `$comment`.
SCHEMA_REJECTED_PACKAGES = ["V069", "V070"]


def main_check(fixtures_dir: str, schemas_dir: str) -> int:
    fails: list[str] = []

    input_schema_path = os.path.join(schemas_dir, "input", "verifier-request.schema.json")
    output_schema_path = os.path.join(schemas_dir, "output", "verifier-result.schema.json")

    cert_schema_path = os.path.join(schemas_dir, "input", "base-certificate.schema.json")

    input_schema = json.load(open(input_schema_path, encoding="utf-8"))
    output_schema = json.load(open(output_schema_path, encoding="utf-8"))
    cert_schema = json.load(open(cert_schema_path, encoding="utf-8"))
    material_schema_path = os.path.join(schemas_dir, "input", "settlement-material.schema.json")
    material_schema = json.load(open(material_schema_path, encoding="utf-8"))
    package_schema_path = os.path.join(schemas_dir, "input", "verification-package.schema.json")
    package_schema = json.load(open(package_schema_path, encoding="utf-8"))

    # 1. schemas are themselves valid Draft 2020-12
    for label, schema in (("input", input_schema), ("output", output_schema),
                          ("base-certificate", cert_schema),
                          ("settlement-material", material_schema),
                          ("verification-package", package_schema)):
        try:
            jsonschema.Draft202012Validator.check_schema(schema)
            print(f"  [ok ] {label} schema is valid Draft 2020-12")
        except jsonschema.exceptions.SchemaError as e:
            fails.append(f"{label} schema invalid: {e.message}")
            print(f"  [FAIL] {label} schema is NOT valid Draft 2020-12")

    # 2. every fixture input.json validates against the input schema
    v = jsonschema.Draft202012Validator(input_schema)
    inputs = sorted(glob.glob(os.path.join(fixtures_dir, "*", "*", "input.json")))
    n_bad = 0
    for f in inputs:
        errs = list(v.iter_errors(json.load(open(f, encoding="utf-8"))))
        if errs:
            n_bad += 1
            rel = os.path.relpath(f, fixtures_dir)
            fails.append(f"{rel} does not validate: {errs[0].message}")
    mark = "ok " if n_bad == 0 else "FAIL"
    print(f"  [{mark}] {len(inputs) - n_bad}/{len(inputs)} fixture input.json validate against the input schema")

    # 3. base certificates against the certificate schema
    cv = jsonschema.Draft202012Validator(cert_schema)
    positives = sorted(glob.glob(os.path.join(fixtures_dir, "conformance", "*", "artifacts",
                                              "base-certificate.json")))
    n_bad = 0
    for f in positives:
        errs = list(cv.iter_errors(json.load(open(f, encoding="utf-8"))))
        if errs:
            n_bad += 1
            fails.append(f"{os.path.relpath(f, fixtures_dir)} does not validate: {errs[0].message}")
    mark = "ok " if n_bad == 0 else "FAIL"
    print(f"  [{mark}] {len(positives) - n_bad}/{len(positives)} positive base certificates validate against the certificate schema")
    n_bad = 0
    for fid in SCHEMA_REJECTED_CERTIFICATES:
        f = os.path.join(fixtures_dir, "adversarial", fid, "artifacts", "base-certificate.json")
        if cv.is_valid(json.load(open(f, encoding="utf-8"))):
            n_bad += 1
            fails.append(f"adversarial/{fid} base certificate passes the certificate schema")
    mark = "ok " if n_bad == 0 else "FAIL"
    print(f"  [{mark}] {len(SCHEMA_REJECTED_CERTIFICATES) - n_bad}/{len(SCHEMA_REJECTED_CERTIFICATES)} envelope-shape fixtures fail the certificate schema")

    # 4. settlement material against the settlement-material schema
    mv = jsonschema.Draft202012Validator(material_schema)
    positives = sorted(glob.glob(os.path.join(fixtures_dir, "conformance", "*", "artifacts",
                                              "settlement-material.json")))
    n_bad = 0
    for f in positives:
        errs = list(mv.iter_errors(json.load(open(f, encoding="utf-8"))))
        if errs:
            n_bad += 1
            fails.append(f"{os.path.relpath(f, fixtures_dir)} does not validate: {errs[0].message}")
    mark = "ok " if n_bad == 0 else "FAIL"
    print(f"  [{mark}] {len(positives) - n_bad}/{len(positives)} positive settlement materials validate against the settlement-material schema")
    n_bad = 0
    for fid in SCHEMA_REJECTED_MATERIALS:
        f = os.path.join(fixtures_dir, "adversarial", fid, "artifacts", "settlement-material.json")
        if mv.is_valid(json.load(open(f, encoding="utf-8"))):
            n_bad += 1
            fails.append(f"adversarial/{fid} settlement material passes the settlement-material schema")
    mark = "ok " if n_bad == 0 else "FAIL"
    print(f"  [{mark}] {len(SCHEMA_REJECTED_MATERIALS) - n_bad}/{len(SCHEMA_REJECTED_MATERIALS)} material-shape fixtures fail the settlement-material schema")

    # 5. verification packages against the verification-package schema
    pv = jsonschema.Draft202012Validator(package_schema)
    positives = sorted(glob.glob(os.path.join(fixtures_dir, "conformance", "*", "artifacts",
                                              "verification-package.json")))
    n_bad = 0
    for f in positives:
        errs = list(pv.iter_errors(json.load(open(f, encoding="utf-8"))))
        if errs:
            n_bad += 1
            fails.append(f"{os.path.relpath(f, fixtures_dir)} does not validate: {errs[0].message}")
    mark = "ok " if n_bad == 0 and positives else "FAIL"
    if not positives:
        fails.append("no positive fixture carries a verification package")
    print(f"  [{mark}] {len(positives) - n_bad}/{len(positives)} positive verification packages validate against the package schema")
    n_bad = 0
    for fid in SCHEMA_REJECTED_PACKAGES:
        f = os.path.join(fixtures_dir, "adversarial", fid, "artifacts", "verification-package.json")
        if pv.is_valid(json.load(open(f, encoding="utf-8"))):
            n_bad += 1
            fails.append(f"adversarial/{fid} verification package passes the package schema")
    mark = "ok " if n_bad == 0 else "FAIL"
    print(f"  [{mark}] {len(SCHEMA_REJECTED_PACKAGES) - n_bad}/{len(SCHEMA_REJECTED_PACKAGES)} package-shape fixtures fail the package schema")

    print(f"\n{len(fails)} schema failures.")
    if fails:
        for f in fails:
            print(f"  - {f}")
        return 1
    print("Schemas are valid, every fixture request conforms, and the certificate, settlement-material and verification-package schemas separate their shape fixtures.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate the normative JSON Schemas.")
    ap.add_argument("--fixtures", default=None)
    ap.add_argument("--schemas", default=None)
    args = ap.parse_args()
    here = os.path.dirname(os.path.abspath(__file__))
    fx = args.fixtures or os.path.join(here, "..", "fixtures")
    sc = args.schemas or os.path.join(here, "..", "schemas")
    return main_check(fx, sc)


if __name__ == "__main__":
    sys.exit(main())
