# Copyright © 2025-2026 CERTCRYPT, Inc., its affiliates or licensors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Author fixtures/primitives/operator-domain-binding/{vectors,documents}.json
(run with PYTHONPATH=<conformance>/generator).

    cd generator && PYTHONPATH=. python author_operator_domain_binding_vectors.py \\
        ../fixtures/primitives/operator-domain-binding

What this script computes: bytes. Keys from fixed seeds, the signed payload
(JCS), the signed message, digests, and FIPS 204 deterministic ML-DSA-65
signatures, so a re-run reproduces both files byte for byte.

What it does NOT compute: the expected verdicts. Every `expected` accept/reject,
every rule id and every expected match below is written out by hand from
`operator.domain-binding/1`, and `emit_primitives.py` re-derives each one with
its own implementation of the rules and fails on any disagreement. Deriving the
expectations with the same code that checks them would prove nothing.
"""
import base64
import copy
import datetime
import hashlib
import json
import os
import sys
from collections import OrderedDict

from dilithium_py.ml_dsa import ML_DSA_65

import primitives as P

OUT_DIR = sys.argv[1]

PREFIX = "certcrypt:operator-domain-binding:1|"
ARTIFACT_TYPE = "operator.domain-binding/1"
METHOD = "https-well-known"
SIG_ALG = "ml-dsa-65-fips204-v1"

# Member order of the §4 table. JCS sorts members, so this order only shapes how
# the statements read in this file.
MEMBERS = [
    "artifact_type", "intent", "domain_binding_method", "operator_id",
    "operator_public_key", "domain_ascii", "sequence", "issued_at",
    "valid_until", "signature_alg", "signature_b64",
]
UNSIGNED = [m for m in MEMBERS if m not in ("signature_alg", "signature_b64")]

KEYS = OrderedDict(
    [
        ("operator-a", bytes.fromhex("a1" * 32)),
        ("operator-b", bytes.fromhex("b2" * 32)),
    ]
)
KEYPAIRS = {label: ML_DSA_65.key_derive(seed) for label, seed in KEYS.items()}


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def operator_id(pk: bytes) -> str:
    return "op:" + b64(hashlib.sha3_256(pk).digest()[:16]).rstrip("=")


def t(s: str) -> datetime.datetime:
    return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)


def fmt(d: datetime.datetime) -> str:
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def shift(s: str, **delta) -> str:
    return fmt(t(s) + datetime.timedelta(**delta))


def payload(st: dict) -> bytes:
    return P.jcs_canonicalize_bytes({k: st[k] for k in UNSIGNED})


def sign(st: dict, key: str, prefix: str = PREFIX) -> dict:
    """Sign `st` in place with `key` over prefix || JCS(payload) and return it."""
    _, sk = KEYPAIRS[key]
    st["signature_alg"] = SIG_ALG
    st["signature_b64"] = b64(
        ML_DSA_65.sign(sk, prefix.encode("ascii") + payload(st), deterministic=True))
    return st


def statement(key: str, intent: str, domain_ascii: str, sequence: int,
              issued_at: str, valid_until: str) -> dict:
    pk, _ = KEYPAIRS[key]
    st = OrderedDict(
        [
            ("artifact_type", ARTIFACT_TYPE),
            ("intent", intent),
            ("domain_binding_method", METHOD),
            ("operator_id", operator_id(pk)),
            ("operator_public_key", b64(pk)),
            ("domain_ascii", domain_ascii),
            ("sequence", str(sequence)),
            ("issued_at", issued_at),
            ("valid_until", valid_until),
        ]
    )
    return sign(st, key)


def text(st: dict) -> str:
    """A statement as compact JSON in the §4 member order (not JCS)."""
    return json.dumps(st, separators=(",", ":"), ensure_ascii=False)


T0 = "2026-11-18T10:00:00Z"
T0_90D = "2027-02-16T10:00:00Z"   # T0 + 90 days exactly

# ── 1. statement construction ─────────────────────────────────────────────
# (label, key, intent, domain as the operator typed it, expected domain_ascii,
#  sequence, issued_at, valid_until, what the case shows)
CONSTRUCTION = [
    ("bind", "operator-a", "bind", "Node.Example.ORG.", "node.example.org", 7, T0, T0_90D,
     "A bind valid for exactly 90 days. The typed host name is upper case with a trailing dot; the statement "
     "carries its canonical form."),
    ("bind-same-sequence-other-content", "operator-a", "bind", "node.example.org", "node.example.org", 7, T0,
     "2027-02-15T10:00:00Z",
     "Same operator and sequence as `bind`, one day shorter: a different statement_digest under the same "
     "identity pair, which is what §7.2 calls a conflict."),
    ("unbind", "operator-a", "unbind", "node.example.org", "node.example.org", 8, "2026-11-20T10:00:00Z",
     "2026-12-20T10:00:00Z",
     "The withdrawal of `bind`, one sequence higher."),
    ("first-bind", "operator-a", "bind", "nodes.example.org", "nodes.example.org", 1, T0, T0_90D,
     "The first statement of a key: sequence 1, issued at the instant it is signed, valid for the 90-day "
     "maximum. A node that signs its first bind for this host at T0 produces exactly this signed payload."),
    ("bind-idn", "operator-b", "bind", "Bücher.Example.ORG", "xn--bcher-kva.example.org", 1, T0,
     "2026-12-18T10:00:00Z",
     "An internationalized host name, carried as its A-label after UTS #46 processing (mapping folds the case)."),
    ("bind-other-operator", "operator-b", "bind", "node.example.org", "node.example.org", 3, T0,
     "2027-01-18T10:00:00Z",
     "Another operator key declaring the same host, as during a change of operator key (§8.1)."),
    ("bind-other-host", "operator-a", "bind", "other.example.org", "other.example.org", 9, T0,
     "2027-01-18T10:00:00Z",
     "The same operator key declaring another host name."),
    ("bind-earlier", "operator-a", "bind", "node.example.org", "node.example.org", 5, T0,
     "2027-01-18T10:00:00Z",
     "A bind of the same host below `bind`, never accepted: what a replay of an older statement looks like."),
]

built = OrderedDict()
construction_cases = []
for label, key, intent, typed, domain_ascii, seq, ia, vu, why in CONSTRUCTION:
    st = statement(key, intent, domain_ascii, seq, ia, vu)
    built[label] = st
    pl = payload(st)
    msg = PREFIX.encode("ascii") + pl
    pk, _ = KEYPAIRS[key]
    case = OrderedDict(
        [
            ("label", label),
            ("what_it_shows", why),
            ("inputs", OrderedDict(
                [
                    ("operator_key", key),
                    ("intent", intent),
                    ("domain", typed),
                    ("sequence", seq),
                    ("issued_at", ia),
                    ("valid_until", vu),
                ]
            )),
            ("expected", OrderedDict(
                [
                    ("operator_id", st["operator_id"]),
                    ("domain_ascii", domain_ascii),
                    ("signed_payload_jcs_utf8", pl.decode("utf-8")),
                    ("statement_digest_hex", hashlib.sha3_256(pl).hexdigest()),
                    ("signing_message_utf8", msg.decode("utf-8")),
                    ("signing_message_sha3_256_hex", hashlib.sha3_256(msg).hexdigest()),
                    ("artifact_jcs_utf8", P.jcs_canonicalize_bytes(dict(st)).decode("utf-8")),
                    ("artifact_jcs_sha3_256_hex",
                     hashlib.sha3_256(P.jcs_canonicalize_bytes(dict(st))).hexdigest()),
                    ("signature_b64", st["signature_b64"]),
                    ("signature_verifies", True),
                ]
            )),
            ("statement", st),
        ]
    )
    construction_cases.append(case)

# One tampered copy of `bind`: a single bit of the signature flipped.
tampered = copy.deepcopy(built["bind"])
sig = bytearray(base64.b64decode(tampered["signature_b64"]))
sig[100] ^= 0x01
tampered["signature_b64"] = b64(bytes(sig))
construction_cases[0]["tampered"] = OrderedDict(
    [
        ("what_it_shows", "Bit 0 of byte 100 of the signature flipped; nothing else changed. It must not verify."),
        ("statement", tampered),
        ("expected_signature_verifies", False),
    ]
)

# ── 2. statement validity ─────────────────────────────────────────────────
BASE_NOW = "2026-12-01T00:00:00Z"


def variant(base: str = "bind", key: str = "operator-a", resign: bool = True, **changes) -> dict:
    st = copy.deepcopy(built[base])
    for k, v in changes.items():
        st[k] = v
    if resign:
        sign(st, key)
    return st


validity_cases = []


def vcase(label, st_or_text, expected, rule, why, now=BASE_NOW):
    body = st_or_text if isinstance(st_or_text, str) else text(st_or_text)
    validity_cases.append(OrderedDict(
        [
            ("label", label),
            ("what_it_shows", why),
            ("now", now),
            ("statement_json_utf8", body),
            ("expected", OrderedDict([("accepted", expected == "accepted"), ("rule", rule)])),
        ]
    ))


A = "accepted"
R = "rejected"
bind = built["bind"]
unbind = built["unbind"]

vcase("valid-bind", bind, A, None, "The `bind` construction case, checked inside its window.")
vcase("bind-90-days-plus-one-second",
      variant(valid_until=shift(T0_90D, seconds=1)), R, "7.1-bind-max-validity",
      "valid_until one second beyond 90 days after issued_at.")
vcase("unbind-91-days", variant("unbind", valid_until=shift(unbind["issued_at"], days=91)), A, None,
      "The 90-day limit applies to a bind only.", now="2026-11-21T00:00:00Z")
vcase("issued-at-equals-valid-until", variant(valid_until=T0), R, "7.1-order",
      "issued_at must be strictly earlier than valid_until.", now=T0)
vcase("unbind-valid-until-before-issued-at",
      variant("unbind", valid_until=shift(unbind["issued_at"], seconds=-1)), R, "7.1-order",
      "The order rule applies to an unbind too.", now="2026-11-21T00:00:00Z")
vcase("issued-at-five-minutes-ahead", bind, A, None,
      "issued_at exactly five minutes after now is within the tolerance.", now=shift(T0, seconds=-300))
vcase("issued-at-beyond-tolerance", bind, R, "7.1-future",
      "issued_at five minutes and one second after now.", now=shift(T0, seconds=-301))
vcase("last-second-of-window", bind, A, None, "now one second before valid_until.",
      now=shift(T0_90D, seconds=-1))
vcase("expired-at-valid-until", bind, R, "7.1-expired",
      "now equal to valid_until: the window is half-open (§10.1 intervals end at valid_until, §10.2).",
      now=T0_90D)
vcase("unbind-expired", unbind, R, "7.1-expired",
      "An unbind whose valid_until has passed can no longer be accepted for the first time (§7.3).",
      now=unbind["valid_until"])
vcase("sequence-leading-zero", variant(sequence="07"), R, "7.2-sequence",
      "A decimal string without leading zeros.")
vcase("sequence-zero", variant(sequence="0"), R, "7.2-sequence", "The lowest sequence is 1.")
vcase("sequence-above-maximum", variant(sequence="9007199254740992"), R, "7.2-sequence",
      "One above 2^53 - 1.")
vcase("sequence-at-maximum", variant(sequence="9007199254740991"), A, None, "Exactly 2^53 - 1.")
vcase("sequence-as-json-number",
      text(bind).replace('"sequence":"7"', '"sequence":7'), R, "4-members",
      "A member of the wrong type. The signature is the original one: the statement is refused before it "
      "is checked.")
vcase("issued-at-fractional-seconds", variant(issued_at="2026-11-18T10:00:00.000Z"), R, "4-values",
      "Instants carry whole seconds and no fraction.")
vcase("issued-at-with-offset", variant(issued_at="2026-11-18T11:00:00+01:00"), R, "4-values",
      "The same instant written with an offset: instants are UTC with `Z`.")
missing = copy.deepcopy(bind)
del missing["domain_binding_method"]
vcase("missing-member", text(missing), R, "4-members",
      "domain_binding_method absent. The original signature is kept; the member set is checked first.")
extra = copy.deepcopy(bind)
extra["comment"] = "x"
vcase("additional-member", text(extra), R, "4-members", "A member outside the closed set of §4.")
vcase("duplicate-member-same-value",
      text(bind).replace('"intent":"bind",', '"intent":"bind","intent":"bind",'), R, "4-members",
      "`intent` twice with the same value. A duplicate member name is refused whatever the values.")
vcase("duplicate-member-other-value",
      text(bind).replace('"domain_ascii":"node.example.org",',
                         '"domain_ascii":"other.example.org","domain_ascii":"node.example.org",'),
      R, "4-members",
      "`domain_ascii` twice with different values: a parser that keeps the last one would see the signed host.")
vcase("intent-outside-set", variant(intent="rebind"), R, "4-values", "intent is `bind` or `unbind`.")
vcase("method-outside-set", variant(domain_binding_method="dns-txt"), R, "4-values",
      "`https-well-known` is the only method of /1, and it is under the signature.")
vcase("artifact-type-other-version", variant(artifact_type="operator.domain-binding/2"), R, "4-values",
      "Another artifact type.")
vcase("signature-alg-other", variant(resign=False, signature_alg="ml-dsa-87-fips204-v1"), R, "4-values",
      "signature_alg is outside the signed payload, so the signature still verifies; the value is refused "
      "on its own.")
vcase("signature-not-base64", variant(resign=False, signature_b64="!!!"), R, "4-values",
      "signature_b64 is standard base64.")
b_pk, _ = KEYPAIRS["operator-b"]
vcase("operator-id-not-derived", variant(operator_id=operator_id(b_pk)), R, "6-operator-id",
      "operator_id of another key, signed correctly by the carried key.")
vcase("public-key-of-another-operator", variant(key="operator-b", operator_public_key=b64(b_pk)), R,
      "6-operator-id",
      "The key and signature of operator-b under operator-a's identifier: the signature verifies, the "
      "identifier does not derive from the key.")
vcase("host-name-not-canonical", variant(domain_ascii="Node.example.org"), R, "5-host-name",
      "A carried host name with an upper-case letter, correctly signed.")
vcase("host-name-is-icann-public-suffix", variant(domain_ascii="co.uk"), R, "5-public-suffix",
      "A carried host name that is itself a public suffix of the ICANN section, correctly signed.")
vcase("signature-bit-flipped", construction_cases[0]["tampered"]["statement"], R, "6-signature",
      "The tampered copy of the construction case.")
st = variant()
st["domain_ascii"] = "other.example.org"
vcase("payload-changed-after-signing", st, R, "6-signature",
      "domain_ascii changed after signing, signature kept.")
st = copy.deepcopy(bind)
_, a_sk = KEYPAIRS["operator-a"]
st["signature_b64"] = b64(ML_DSA_65.sign(a_sk, payload(st), deterministic=True))
vcase("signed-without-prefix", st, R, "6-signature",
      "A valid signature over signed_payload_jcs alone, without the domain-separation prefix. It verifies "
      "over those bytes and not over the signed message.")
vcase("signed-under-another-prefix", sign(copy.deepcopy(bind), "operator-a",
                                          prefix="certcrypt:operator-domain-binding:2|"), R, "6-signature",
      "A valid signature under a prefix of another version.")
vcase("signed-by-another-key", sign(copy.deepcopy(bind), "operator-b"), R, "6-signature",
      "Signed by operator-b, carrying operator-a's key and identifier.")

# ── 3. host names ─────────────────────────────────────────────────────────
NON_PUBLIC_TLDS = ["localhost", "invalid", "test", "local", "arpa", "onion", "alt", "internal"]

# What the operator typed → the producer's domain_ascii, or a refusal.
input_cases = []


def icase(label, typed, expected_ascii, rule, why):
    input_cases.append(OrderedDict(
        [
            ("label", label),
            ("what_it_shows", why),
            ("input", typed),
            ("expected", OrderedDict(
                [("domain_ascii", expected_ascii), ("rule", rule)]
            )),
        ]
    ))


icase("ascii", "node.example.org", "node.example.org", None, "Already canonical.")
icase("upper-case", "Node.Example.ORG", "node.example.org", None, "Mapping folds the case.")
icase("trailing-dot", "node.example.org.", "node.example.org", None,
      "The carried form has no trailing dot.")
icase("idn", "bücher.example.org", "xn--bcher-kva.example.org", None, "A U-label becomes its A-label.")
icase("idn-upper-case", "BÜCHER.example.org", "xn--bcher-kva.example.org", None,
      "Case folding happens before the conversion.")
icase("idn-non-transitional", "faß.example.org", "xn--fa-hia.example.org", None,
      "Non-transitional processing keeps U+00DF; transitional processing would have produced `fass`.")
icase("a-label-input", "xn--bcher-kva.example.org", "xn--bcher-kva.example.org", None,
      "An A-label typed as such is kept.")
icase("check-hyphens-leading", "-node.example.org", None, "5-idna", "CheckHyphens: no leading hyphen.")
icase("check-hyphens-third-fourth", "ab--c.example.org", None, "5-idna",
      "CheckHyphens: no hyphens in the third and fourth positions of a label that is not an A-label.")
icase("check-bidi", "a\u05d0.example.org", None, "5-idna",
      "CheckBidi: a left-to-right label with a right-to-left character.")
icase("check-joiners", "a\u200db.example.org", None, "5-idna",
      "CheckJoiners: ZERO WIDTH JOINER outside the context that allows it.")
icase("bidi-formatting-character", "a\u202eb.example.org", None, "5-idna",
      "A bidirectional formatting character (RIGHT-TO-LEFT OVERRIDE) is disallowed.")
icase("control-character", "a\u0007b.example.org", None, "5-idna", "A control character is disallowed.")
icase("empty-label", "a..example.org", None, "5-idna", "VerifyDnsLength: an empty label.")
icase("label-over-63", ("a" * 64) + ".example.org", None, "5-idna", "VerifyDnsLength: a 64-octet label.")
icase("name-over-253", ".".join(["a" * 63] * 4) + ".org", None, "5-idna",
      "VerifyDnsLength: 256 octets in all.")
icase("wildcard", "*.example.org", None, "5-wildcard", "A wildcard label.")
icase("underscore", "_acme.example.org", None, "5-underscore", "An underscore.")
icase("single-label", "node", None, "5-single-label", "Not a fully qualified host name.")
icase("empty", "", None, "5-empty", "Nothing typed.")

# A carried domain_ascii → accepted or refused by a consumer.
carried_cases = []


def ccase(label, domain, accepted, rule, why):
    carried_cases.append(OrderedDict(
        [
            ("label", label),
            ("what_it_shows", why),
            ("domain_ascii", domain),
            ("expected", OrderedDict([("accepted", accepted), ("rule", rule)])),
        ]
    ))


ccase("canonical", "node.example.org", True, None, "Lower-case ASCII labels.")
ccase("a-label", "xn--bcher-kva.example.org", True, None, "An A-label.")
ccase("registrable-under-icann-suffix", "example.co.uk", True, None,
      "A name under an ICANN public suffix, not one itself.")
ccase("private-section-suffix", "github.io", True, None,
      "A public suffix of the PRIVATE section (a multi-tenant platform) is associated exactly as declared "
      "(§5 names the ICANN section only; §11).")
ccase("name-under-private-suffix", "node.github.io", True, None, "A name under a private-section suffix.")
ccase("wildcard-exception", "www.ck", True, None,
      "`!www.ck` is an exception to `*.ck`: not a public suffix.")
ccase("upper-case", "Node.example.org", False, "5-host-name", "Not the lower-case A-label form.")
ccase("trailing-dot", "node.example.org.", False, "5-host-name", "A trailing dot.")
ccase("u-label", "bücher.example.org", False, "5-host-name", "A U-label is not the carried form.")
ccase("single-label", "org", False, "5-host-name", "A single label.")
ccase("home-arpa", "node.home.arpa", False, "5-host-name", "Under arpa, including home.arpa (RFC 8375).")
ccase("ipv4-literal", "192.0.2.1", False, "5-host-name",
      "An IPv4 address literal (its top-level label is all-numeric too).")
ccase("ipv6-literal", "[2001:db8::1]", False, "5-host-name", "An IPv6 address literal.")
ccase("numeric-tld", "node.123", False, "5-host-name", "An all-numeric top-level label.")
ccase("wildcard", "*.example.org", False, "5-host-name", "A wildcard label.")
ccase("underscore", "_acme.example.org", False, "5-host-name", "An underscore.")
ccase("hyphens-third-fourth", "ab--c.example.org", False, "5-host-name",
      "Hyphens in the third and fourth positions of a label that is not an A-label.")
ccase("empty", "", False, "5-host-name", "Empty.")
ccase("icann-public-suffix", "co.uk", False, "5-public-suffix",
      "Itself a public suffix of the ICANN section.")
ccase("icann-wildcard-suffix", "nodes.ck", False, "5-public-suffix",
      "Itself a public suffix through the ICANN wildcard rule `*.ck`.")

host_names = OrderedDict(
    [
        ("non_public_top_level_names", OrderedDict(
            [
                ("what_it_shows",
                 "Every top-level name §5 lists as never resolving in the public DNS. Build `node.<name>` for "
                 "each: a producer refuses it as input and a consumer refuses it as a carried domain_ascii. "
                 "The names are listed rather than spelled out as host names."),
                ("template", "node.{name}"),
                ("names", NON_PUBLIC_TLDS),
                ("expected", OrderedDict(
                    [("input", OrderedDict([("domain_ascii", None), ("rule", "5-non-public-tld")])),
                     ("carried", OrderedDict([("accepted", False), ("rule", "5-host-name")]))]
                )),
            ]
        )),
        ("public_suffix_list_excerpt", OrderedDict(
            [
                ("what_it_shows",
                 "The Public Suffix List rules the carried cases depend on, by section. A consumer uses the "
                 "full list; these rules have been stable in it for years and are enough to recompute every "
                 "`5-public-suffix` case with the standard algorithm (longest matching rule, exceptions win, "
                 "default rule `*`)."),
                ("icann", ["org", "uk", "co.uk", "io", "ck", "*.ck", "!www.ck"]),
                ("private", ["github.io"]),
            ]
        )),
        ("input_cases", input_cases),
        ("carried_cases", carried_cases),
    ]
)

# ── 4. sequence (§7.2 and §9 step 3) ──────────────────────────────────────
def ref(label: str) -> OrderedDict:
    st = built[label]
    return OrderedDict(
        [
            ("statement", label),
            ("operator_id", st["operator_id"]),
            ("sequence", st["sequence"]),
            ("intent", st["intent"]),
            ("domain_ascii", st["domain_ascii"]),
            ("statement_digest_hex", hashlib.sha3_256(payload(st)).hexdigest()),
        ]
    )


sequence_cases = []


def scase(label, accepted, received, result, why):
    sequence_cases.append(OrderedDict(
        [
            ("label", label),
            ("what_it_shows", why),
            ("accepted", [ref(x) for x in accepted]),
            ("received", ref(received)),
            ("expected", result),
        ]
    ))


scase("first-statement", [], "bind", "candidate", "No state for the operator: accepted as a candidate.")
scase("higher-sequence", ["first-bind"], "bind", "candidate", "7 after 1: higher than the highest accepted.")
scase("lower-sequence", ["bind"], "first-bind", "rejected", "1 after 7: lower than the highest accepted.")
scase("same-sequence-same-digest", ["bind"], "bind", "idempotent",
      "The same statement again: nothing changes.")
scase("same-sequence-other-content", ["bind"], "bind-same-sequence-other-content", "conflict",
      "Sequence 7 again with a different statement_digest.")
scase("sequences-are-per-operator", ["bind-other-host"], "bind-other-operator", "candidate",
      "operator-a has accepted 9; operator-b's 3 is compared with operator-b's statements only.")
scase("unbind-after-bind", ["bind"], "unbind", "candidate", "The unbind (8) is higher than the bind (7).")
scase("older-bind-after-unbind", ["bind", "unbind"], "bind-earlier", "rejected",
      "A bind (5) never accepted, lower than the accepted unbind (8): an older bind cannot revive the binding.")
scase("accepted-statement-again-below-highest", ["first-bind", "bind"], "first-bind", "idempotent",
      "Sequence 1 was accepted before 7. Presented again with the same digest it is idempotent, although 1 is "
      "lower than the highest accepted: the first row of the table decides.")
scase("conflict-below-highest", ["bind", "unbind"], "bind-same-sequence-other-content", "conflict",
      "Sequence 7 with a different digest after 8 was accepted: a conflict, not merely a lower sequence.")

unbind_precedence_cases = [
    OrderedDict(
        [
            ("label", "accepted-unbind-blocks-lower-bind"),
            ("what_it_shows",
             "§9 step 3: the bind (7) was accepted, then an unbind (8) naming the same host. The bind no longer "
             "establishes the binding even if the origin still serves it."),
            ("accepted", [ref("bind"), ref("unbind")]),
            ("checked", ref("bind")),
            ("expected_established", False),
        ]
    ),
    OrderedDict(
        [
            ("label", "unbind-of-another-host-does-not-block"),
            ("what_it_shows",
             "An unbind withdraws the association to the host it names and to no other (§7.3)."),
            ("accepted", [ref("bind"), ref("unbind"), ref("bind-other-host")]),
            ("checked", ref("bind-other-host")),
            ("expected_established", True),
        ]
    ),
]

vectors = OrderedDict(
    [
        ("profile", "operator.domain-binding/1"),
        ("specification_status", "Draft"),
        ("description",
         "The statement by which an operator key declares an HTTPS origin's host name, and the checks a third "
         "party performs on it. The operator key signs the statement; the origin publishes it; anyone holding "
         "the operator identifier checks that both declare each other. Not part of an independence proof and "
         "no input to its verification."),
        ("rules", OrderedDict(
            [
                ("operator_id", "op: + STANDARD_NO_PAD(SHA3-256(operator_public_key_bytes)[0..16]) "
                                "(operator.recognition/1 §3.2)."),
                ("signed_payload", "JCS (RFC 8785) of the statement without signature_alg and signature_b64."),
                ("signed_message", "The ASCII prefix `certcrypt:operator-domain-binding:1|` followed by the "
                                   "signed payload (operator.recognition/1 §10)."),
                ("statement_digest", "SHA3-256 of the signed payload. With (operator_id, sequence) it is the "
                                     "statement's identity; signature_alg and signature_b64 are outside it."),
                ("signature", "ML-DSA-65 (FIPS 204), empty context, by the operator key over the signed "
                              "message, standard base64. The signatures here use the deterministic variant so "
                              "the files reproduce; a conforming signer may hedge, so an implementation "
                              "verifies signatures and compares bytes only for what is deterministic."),
                ("rule_ids", "Each refusal names the clause that decides it: 4-members (member set, duplicate "
                             "names, types), 4-values (fixed values and formats), 5-* (host name; "
                             "5-public-suffix is the ICANN Public Suffix List rule), 6-operator-id, "
                             "6-signature, 7.1-order, 7.1-bind-max-validity, 7.1-future, 7.1-expired, "
                             "7.2-sequence."),
            ]
        )),
        ("constants", OrderedDict(
            [
                ("artifact_type", ARTIFACT_TYPE),
                ("domain_binding_method", METHOD),
                ("signature_alg", SIG_ALG),
                ("signing_prefix", PREFIX),
                ("well_known_path", "/.well-known/certcrypt-node.json"),
                ("well_known_max_bytes", 65536),
                ("well_known_max_entries", 8),
                ("bind_max_validity_days", 90),
                ("issued_at_future_tolerance_seconds", 300),
                ("sequence_max", "9007199254740991"),
            ]
        )),
        ("keys", [
            OrderedDict(
                [
                    ("label", label),
                    ("seed_hex", seed.hex()),
                    ("public_key_b64", b64(KEYPAIRS[label][0])),
                    ("operator_id", operator_id(KEYPAIRS[label][0])),
                ]
            )
            for label, seed in KEYS.items()
        ]),
        ("construction", OrderedDict(
            [
                ("what_it_checks",
                 "From fixed inputs, the exact bytes a producer signs and a consumer recomputes. The key is the "
                 "FIPS 204 key generated from seed_hex (the seed is the 32-byte xi)."),
                ("cases", construction_cases),
            ]
        )),
        ("statement_validity", OrderedDict(
            [
                ("what_it_checks",
                 "Every check of §4 to §7.1 a consumer makes on one statement at instant `now`, with no state: "
                 "the member set parsed from the exact JSON text, the values, the host name, operator_id "
                 "against the carried key, the signature under that key, and the validity window. Each "
                 "refused case breaks one rule and keeps the others; where a case changes a signed member it "
                 "is signed again, so the signature does not decide it."),
                ("cases", validity_cases),
            ]
        )),
        ("host_names", host_names),
        ("sequence", OrderedDict(
            [
                ("what_it_checks",
                 "The table of §7.2 for a party that keeps state per operator_id, and §9 step 3. `accepted` "
                 "lists the statements already accepted, in order; `received` is the next one. Results: "
                 "`candidate`, `idempotent`, `conflict`, `rejected`. Statements are named by their "
                 "construction label and carry the identity the rule reads."),
                ("cases", sequence_cases),
                ("unbind_precedence_cases", unbind_precedence_cases),
            ]
        )),
    ]
)

# ── 5. the published document ─────────────────────────────────────────────


def doc_body(*statements, extra=None) -> str:
    d = {"bindings": list(statements)}
    if extra:
        d.update(extra)
    return P.jcs_canonicalize_bytes(d).decode("utf-8")


fillers = []
for i in range(1, 8):
    fillers.append(statement("operator-b", "bind", f"n{i}.example.org", 10 + i, T0, "2027-01-18T10:00:00Z"))

placeholder = OrderedDict((m, "A") for m in MEMBERS)

document_cases = []
HOST = "node.example.org"
NOW = BASE_NOW


def dcase(label, why, body, query_key, checked, valid, rule, match, now=NOW, host=HOST, construction=None):
    case = OrderedDict(
        [
            ("label", label),
            ("what_it_shows", why),
            ("host", host),
            ("operator_id", operator_id(KEYPAIRS[query_key][0])),
            ("now", now),
            ("checked_statement", checked),
        ]
    )
    if construction is not None:
        case["body_construction"] = construction
    else:
        case["body_utf8"] = body
    case["expected"] = OrderedDict(
        [
            ("document_accepted", valid),
            ("document_rule", rule),
            ("matching_statement_digest_hex",
             hashlib.sha3_256(payload(built[match])).hexdigest() if match else None),
        ]
    )
    document_cases.append(case)


single = doc_body(bind)
dcase("match", "One statement, by the operator in question, for the fetched host, valid at now.",
      single, "operator-a", "bind", True, None, "bind")
dcase("match-among-other-operators",
      "Two operators declare the host; the other operator's statement is ignored.",
      doc_body(built["bind-other-operator"], bind), "operator-a", "bind", True, None, "bind")
dcase("other-operator-queried", "The same document checked for operator-b.",
      doc_body(built["bind-other-operator"], bind), "operator-b", "bind-other-operator", True, None,
      "bind-other-operator")
dcase("only-other-operators", "Only another operator's statement: nothing matches operator-a.",
      doc_body(built["bind-other-operator"]), "operator-a", "bind", True, None, None)
dcase("domain-mismatch", "operator-a's valid statement for other.example.org, served at node.example.org.",
      doc_body(built["bind-other-host"]), "operator-a", "bind", True, None, None)
dcase("statement-expired", "now is the statement's valid_until.", single, "operator-a", "bind", True, None,
      None, now=T0_90D)
dcase("statement-not-yet-valid", "now is five minutes and one second before issued_at.", single,
      "operator-a", "bind", True, None, None, now=shift(T0, seconds=-301))
dcase("signature-does-not-verify", "The served statement has one bit of its signature flipped.",
      doc_body(construction_cases[0]["tampered"]["statement"]), "operator-a", "bind", True, None, None)
dcase("unbind-only", "Only an unbind for the host: an unbind never opens an association (§7.3, §9 step 2).",
      doc_body(unbind), "operator-a", "bind", True, None, None, now="2026-11-21T00:00:00Z")
dcase("eight-entries", "Eight statements, the most a document may carry.",
      doc_body(bind, *fillers), "operator-a", "bind", True, None, "bind")
dcase("nine-entries",
      "Nine entries. Nine real statements cannot fit in 65 536 bytes (an ML-DSA-65 key and signature alone "
      "take about 7 KiB of base64), so the extra ones are short placeholders: the document stays under the "
      "byte limit and only the entry limit refuses it.",
      doc_body(bind, *([placeholder] * 8)), "operator-a", "bind", False, "8.1-entries", None)
dcase("no-entries", "`bindings` empty: one to eight statements.", doc_body(), "operator-a", "bind", False,
      "8.1-entries", None)
dcase("at-byte-limit", "The `match` document followed by spaces up to exactly 65 536 bytes.", None,
      "operator-a", "bind", True, None, "bind",
      construction=OrderedDict([("from_case", "match"), ("append_spaces_to_total_bytes", 65536)]))
dcase("over-byte-limit", "The same, 65 537 bytes.", None, "operator-a", "bind", False, "8.1-size", None,
      construction=OrderedDict([("from_case", "match"), ("append_spaces_to_total_bytes", 65537)]))
dcase("duplicate-top-level-member", "`bindings` twice.",
      '{"bindings":[' + text(bind) + '],"bindings":[' + text(bind) + "]}", "operator-a", "bind", False,
      "8.2-duplicate", None)
dcase("duplicate-member-in-statement", "A statement with `sequence` twice inside an otherwise valid document.",
      '{"bindings":[' + text(bind).replace('"sequence":"7",', '"sequence":"7","sequence":"7",') + "]}",
      "operator-a", "bind", False, "8.2-duplicate", None)
dcase("additional-top-level-member", "A member besides `bindings`.",
      doc_body(bind, extra={"comment": "x"}), "operator-a", "bind", False, "8.1-format", None)
dcase("top-level-array", "An array instead of an object.", "[" + text(bind) + "]", "operator-a", "bind",
      False, "8.1-format", None)
dcase("malformed-entry-beside-match",
      "The matching statement next to an entry without `domain_binding_method`: one element that is not a "
      "well-formed statement makes the whole resource malformed (§8.1), so nothing matches.",
      '{"bindings":[' + text(bind) + "," + text(missing) + "]}", "operator-a", "bind", False,
      "8.1-statement", None)

# What a party that keeps state concludes about the statement it looks for
# (§8.3, §10.2): `matched`; `absent` (a valid resource without its digest);
# `malformed` (the resource is refused, or carries its digest in an entry that
# fails a check: an unknown state that neither ends nor extends an interval);
# `expired` (carried, its only defect being that valid_until has passed).
CHECKED_STATE = {
    "match": "matched",
    "match-among-other-operators": "matched",
    "other-operator-queried": "matched",
    "only-other-operators": "absent",
    "domain-mismatch": "absent",
    "statement-expired": "expired",
    "statement-not-yet-valid": "malformed",
    "signature-does-not-verify": "malformed",
    "unbind-only": "absent",
    "eight-entries": "matched",
    "nine-entries": "malformed",
    "no-entries": "malformed",
    "at-byte-limit": "matched",
    "over-byte-limit": "malformed",
    "duplicate-top-level-member": "malformed",
    "duplicate-member-in-statement": "malformed",
    "additional-top-level-member": "malformed",
    "top-level-array": "malformed",
    "malformed-entry-beside-match": "malformed",
}
assert set(CHECKED_STATE) == {c["label"] for c in document_cases}
for c in document_cases:
    c["expected"]["checked_statement_state"] = CHECKED_STATE[c["label"]]

documents = OrderedDict(
    [
        ("profile", "operator.domain-binding/1"),
        ("specification_status", "Draft"),
        ("what_it_checks",
         "The published resource of §8.1 and the matching of §8.3 and §9 step 2, offline: given the bytes the "
         "origin served for `host`, the operator identifier in question and the instant `now`, whether the "
         "document is acceptable at all and which statement, if any, matches — its domain_ascii equals the "
         "host, its operator_id is the one in question, its intent is bind, it passes every check of "
         "statement_validity, and it is within its window. `checked_statement` names the construction case a "
         "party that keeps state registered and is now looking for, and `checked_statement_state` what that "
         "party concludes about it: `matched`; `absent` (a valid resource that carries no entry with its "
         "digest); `malformed` (the resource is refused, or carries its digest in an entry that fails a check — "
         "an unknown state that neither ends nor extends an association); `expired` (carried, and its only "
         "defect is that valid_until has passed). Document rules: 8.1-size, 8.1-format, 8.1-entries, "
         "8.1-statement (an element that is not a well-formed statement), 8.2-duplicate. The statements are "
         "the construction cases of vectors.json; `body_construction` rebuilds a body from another case's "
         "bytes."),
        ("cases", document_cases),
    ]
)

os.makedirs(OUT_DIR, exist_ok=True)
for name, obj in (("vectors.json", vectors), ("documents.json", documents)):
    with open(os.path.join(OUT_DIR, name), "w", encoding="utf-8") as fh:
        # ASCII only: some host-name inputs are invisible or reorder text
        # (joiners, bidirectional controls), and they must stay visible as escapes.
        json.dump(obj, fh, indent=2, ensure_ascii=True)
        fh.write("\n")
print("construction:", len(construction_cases), "validity:", len(validity_cases),
      "host input:", len(input_cases), "host carried:", len(carried_cases),
      "non-public names:", len(NON_PUBLIC_TLDS), "sequence:", len(sequence_cases) + len(unbind_precedence_cases),
      "documents:", len(document_cases))
