# Verifying policy approvals

This guide is for Maskura customers who want to verify policy-approval
history **offline**, with tools they control. It covers the `maskura policy`
command group and the local trust store it maintains.

## What verification establishes — and what it does not

**Claim:** customer-verifiable approval history against customer-retained
checkpoints — every checked receipt was approved by a signer anchored to your
own pinned trust root, consistent with the checkpoints you retained yourself.

**Non-claims:**

- **Not execution attestation.** A verified receipt says a signer approved a
  policy state change. It does not prove what code ran, what bytes were
  processed, or that an operation used the approved state. A compromised
  gateway can still serve unapproved bytes in real time; verification makes
  that contradiction forensically visible afterwards — detection, not
  prevention ([ADR 0022](adr/0022-policy-approval-and-execution-trust-boundary.md)).
- **Not witness-verified.** The external consistency witness is a separately
  gated program and is not implemented. Report output always carries
  `witness: not-witness-verified`. Optional witness acknowledgement records
  in an artifact parse, but their absence is never blocking and their
  presence never upgrades the status.
- **No completeness claim without retained checkpoints.** With no prior
  checkpoint the report says `completeness: UNVERIFIED (no prior checkpoint)`
  and never reports the history as complete. Hash chains establish consistency
  against the checkpoints you retained; they do not alone establish complete
  or latest history or prevent split views.
- **No operator-trust expansion.** The gateway and its operator remain trusted
  during processing ([docs/security.md](security.md)).

## Install and prerequisites

The `maskura` CLI ships with Maskura (v0.7.24+). You need:

- an **EvidenceBundle** export (`.json`) obtained through your own channel —
  the export offered after a publish approval in the hosted dashboard;
- no network access and no gateway account: verification is fully offline.

## The trust store

`~/.config/maskura/policy/` (override with `--trust-dir <dir>` or
`MASKURA_POLICY_TRUST_DIR`) is a plain, portable directory. Copy or back it
up freely; it contains no secrets.

```
policy/
  trust.json                     # pinned trust roots (workspace → fingerprint)
  checkpoints/<workspace>/<seq>.json   # retained checkpoints, append-only
  index.json                     # imported artifact digests (audit/dedupe)
```

- `trust.json` records one pin per workspace: the trust-root fingerprint
  (SHA-256 hex of the canonical trust bundle) and an imported COSE trust
  bundle snapshot.
- Checkpoints are **append-only by sequence**: a sequence slot is never
  overwritten (identical re-imports are no-ops). The highest retained
  sequence is your effective head.
- On a forced root replacement the previous lineage's checkpoints are moved
  to `checkpoints/<workspace>-retired-<fingerprint8>/` and remain separately
  verifiable ([ADR 0024](adr/0024-trust-root-lineage-and-receipt-head-retention.md)).

## Establishing a trust root (pins)

**A pin is written only from customer-controlled input.**

```bash
# First import: verifies the artifact's self-consistency and approval proof,
# then auto-establishes the root pin from your own artifact.
maskura policy trust import ./evidence.json

# Manual/strict equivalent: pin the fingerprint you read off the dashboard's
# fingerprint display (or out of band), optionally attaching the root bundle.
maskura policy trust add <64-hex-fingerprint> --workspace <id> [--bundle trust_root.json]

maskura policy trust show
```

Rules, enforced by the CLI:

- `trust import` verifies the artifact first (container/schema gate, digest
  re-derivation, receipt validation, chain links, approval proof) and only
  then writes the pin. A tampered artifact establishes nothing.
- Overwriting a pin with a **different** fingerprint is refused unless you
  pass `--force` **and** confirm (interactively, or `--yes` for scripts).
  There is never a silent substitution. Accepting a new root is a recorded
  discontinuity (see below).
- `maskura policy trust fetch` downloads a served trust bundle **only** to
  compare or refresh one already matching a local pin. A server-fetched
  bundle can never establish a pin, and a non-matching served bundle changes
  nothing.

## Verifying an export

```bash
maskura policy verify ./evidence.json
maskura policy verify ./evidence.json --at 2026-10-01T00:00:00Z
maskura policy verify ./evidence.json --json
```

Two artifact forms exist (`kind` field):

- `evidence` — one landed publish approval: the receipt, the post-publish
  checkpoint, the approval proof (ASN.1 DER ES256 over
  `authenticatorData || SHA256(clientDataJSON)`, with the retained
  clientDataJSON / authenticator data / credential id / COSE algorithm
  association), and an optional bounded `chain_tail`;
- `chain` — a full receipt-chain export (`receipts[]` + `checkpoints[]`) for
  whole-history verification and gap filling.

Both carry an explicit `schema_version: 1`. Readers fail closed: unknown
schema versions and unknown fields are rejected, not ignored.

Verification runs these steps, each fail-closed with a stable typed finding:

1. container parse + `schema_version`/`kind` gate;
2. canonical-CBOR digest re-derivation over the signed bodies (the
   sorted-JSON-keys convention — explicitly not RFC 8949 canonical CBOR);
3. receipt body validation (effective-state digest equality, checked
   arithmetic, draft rejection);
4. chain links (sequence continuity, `prev_receipt_sha256` linkage, genesis
   shape, checkpoint linkage);
5. approval proof verification (type, origin, RP-ID hash, UP/UV, challenge ↔
   receipt-digest binding, workspace binding) against the COSE key from the
   trust bundle matching your local pin — **unpinned verification is
   refused**;
6. signer transitions (bootstrap/replacement chains; trust resets rendered as
   discontinuities);
7. checkpoint consistency versus your retained heads (`extended-ok` / `gap` /
   `rollback-suspect` / `first-run`);
8. validity at the evaluated instant (`--at`, or now with the ±60 s skew
   convention).

Successful verifications automatically retain the post-publish checkpoint and
record the artifact digest in `index.json`, so your coverage grows as you
verify.

## Reading the report

```
Policy approval verification report
  artifact:      evidence  workspace ws-1  head seq 2 (1f2e3d4c5b6a…)
  evaluated at:  1760160000 (skew ±60s)
  verdict:       VERIFIED
  completeness:  COMPARED (seq 2..=2 against retained head 1)
  witness:       not-witness-verified
```

- `verdict: VERIFIED` — every check passed. Read it together with
  `completeness`.
- `completeness: UNVERIFIED (no prior checkpoint)` — nothing links this
  artifact to your retained history yet (see "First run" below). The history
  is **not** claimed to be complete.
- `completeness: COMPARED (seq N..=M against retained head K)` — the verified
  range was compared against your retained checkpoints; any `gap` or
  `rollback-suspect` findings are fatal and reported.
- `witness: not-witness-verified` — always, until the external witness
  program (separately gated) is implemented and accepted.

With `--json` the report is a stable, versioned object
(`schema_version: 1`) carrying `verdict`, `findings[]`, `completeness`, and
`witness`.

### First run

The first artifact you verify for a workspace has no prior checkpoint. The
report says `completeness: UNVERIFIED (no prior checkpoint)` and a
`first-run` finding states that nothing yet links the artifact to pinned
history. This is deliberate honesty, not an error: your first import is the
bootstrap trust moment, taken from your own dashboard export. Everything
verified afterwards is anchored to the checkpoints you retain from there.

### Gaps and rollback suspicion

- `gap` — your retained history exists but the artifact's range does not link
  to it (missing intermediate receipts). Fatal. Fill the gap with a `chain`
  export covering the missing sequences.
- `rollback-suspect` — the artifact contradicts your retained history: a
  different receipt digest at a sequence you already retained (a split-view
  suspicion), or a head below your retained head that matches no retained
  record. Fatal.

### Historical validity (`--at`)

`--at <unix-seconds | RFC3339-UTC>` evaluates validity at that instant: an
approval issued after the evaluated instant (beyond the ±60 s skew) reports
`not-yet-valid`. The default is now. Receipts are permanent historical
statements — they do not expire; expiry semantics (`policy.expired`) apply to
policy envelopes at request time inside the enforced gateway, not to retained
evidence.

## Trust resets are discontinuities

If all authorized keys for a workspace are lost, recovery is a **new
independently pinned root** — never cryptographic continuity. A reset never
signs an old-chain receipt; the old chain and its retained head stay
separately verifiable.

In the tooling this means:

- verifying an artifact whose root does not match your pin fails with
  `discontinuity: new root not accepted`, and continuity is never presented;
- the new root verifies only after you accept it explicitly
  (`policy trust import --force` + confirmation, or `policy trust add`);
- recorded trust resets inside verified bundles are rendered prominently as
  `discontinuity: trust reset recorded at epoch N (…)` findings — history is
  not continuous across a trust reset;
- accepting a new root archives (never deletes) the previous lineage's
  checkpoints.

## Limitations to keep in mind

- Verification is limited to **detectable** inconsistency against the
  checkpoints you retained. Without an external witness (not implemented), an
  operator equivocating to you alone is not detectable in general; your
  retained checkpoints are the anchor, so verify exports promptly and keep
  the trust store backed up.
- Signature validity does not prove honest display of the policy to the human
  who approved it.
- Approval evidence is not per-operation execution proof, not PII-detection
  completeness, and not a storage acknowledgment.
- Approval receipts land after the configuration publish they approve (the
  publish is not staged behind the signature). An unapproved publish therefore
  leaves **no receipt** — detectable by absence when you compare exports
  against your configuration history — but it is not prevented by the
  ceremony. Workspaces under enforcement cannot serve data from an unapproved
  configuration; closing the configuration-plane gap (staged publish committed
  by the approval) is planned hardening.

## Related records

- [ADR 0022](adr/0022-policy-approval-and-execution-trust-boundary.md) — the
  trust boundary and claims.
- [ADR 0023](adr/0023-policy-approval-verification.md) — the verification
  contract (receipts, checkpoints, proofs).
- [ADR 0024](adr/0024-trust-root-lineage-and-receipt-head-retention.md) —
  trust-root lineage and receipt-head retention across resets.
- [docs/security.md](security.md) — the full security model.
