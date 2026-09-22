# Encrypted Storage Gateway — Project Spec

## 1. Problem

Server-side encryption (S3 default encryption, EBS encryption, etc.) protects data
at rest against someone stealing the physical disk. It does **not** protect against:

- A compromised or overly-permissive IAM role reading the bucket directly.
- An operator with S3 console access browsing files they shouldn't.
- A misconfigured bucket policy (the single most common cause of real cloud
  storage breaches) exposing objects that are "encrypted" but readable, because
  AWS holds the key and applies it transparently on every authorized read.

Server-side encryption answers "is the disk safe if stolen?" It does not answer
"can AWS itself, or anyone with AWS access, read my files?" — the answer today is
almost always yes.

**Goal:** encrypt files *before* they leave the client/application boundary, using
a key AWS's storage layer never sees in plaintext, so that S3 access alone is
insufficient to read the data. This is the same architectural pattern ("envelope
encryption") used by real client-side encryption products, applied at
project scale.

## 2. Core Concept — Envelope Encryption

Two layers of keys, not one:

1. **Data key** — a random 256-bit AES key, generated fresh per file. Used to
   encrypt the actual file bytes (AES-256-GCM). Fast, symmetric, never reused
   across files.
2. **Master key** — lives in AWS KMS, never leaves KMS in plaintext, never
   touches application code or disk. Used only to encrypt/decrypt the (small)
   data key.

Flow on upload:

```
1. Ask KMS to GenerateDataKey
   → KMS returns: plaintext data key + that same key encrypted under the master key
2. Encrypt the file with the plaintext data key (AES-256-GCM) → ciphertext + IV + auth tag
3. Discard the plaintext data key from memory immediately
4. Store in S3: ciphertext, IV, auth tag, and the KMS-encrypted data key
   (the plaintext data key is never written anywhere)
```

Flow on download:

```
1. Read the KMS-encrypted data key from the stored object
2. Ask KMS to Decrypt it → get the plaintext data key back
   (only succeeds if the caller's IAM identity has KMS Decrypt permission)
3. Use the plaintext data key + IV + auth tag to decrypt the ciphertext (AES-256-GCM)
4. Return original bytes; discard plaintext data key from memory
```

**Why this matters:** anyone with only S3 read access sees encrypted garbage and
an encrypted key blob — useless without also having KMS `Decrypt` permission on
the specific master key, which is a separate, narrower, auditable permission.

## 3. What This Protects Against (and What It Doesn't)

Be explicit about the threat model — this honesty is what separates a real
security project from a toy.

**Protects against:**
- Compromised or overly broad AWS credentials that have S3 access but not KMS
  decrypt access on this key.
- A misconfigured/public S3 bucket — an exposed object is still ciphertext.
- An insider (cloud provider employee, teammate) with storage-layer access but
  no KMS grant.
- Tampering — AES-GCM's auth tag makes any modified ciphertext fail to decrypt,
  rather than silently returning corrupted data.

**Does not protect against:**
- A compromised application server that legitimately holds KMS decrypt
  permission — it can call `Decrypt` itself.
- Compromise of the client device before encryption happens.
- Someone with IAM permission to grant themselves KMS access (permission
  hygiene is a separate, prerequisite problem).

## 4. Architecture

```
Client / calling app
   │
   ▼
Gateway API
   POST /objects    → encrypt + upload
   GET  /objects/:id → fetch + decrypt
   │
   ├──► AWS KMS        (GenerateDataKey, Decrypt — master key never leaves KMS)
   ├──► AWS S3          (ciphertext + IV + auth tag + encrypted data key)
   └──► CloudTrail/CloudWatch (KMS access logging — who decrypted what, when)
```

Terraform-managed:
- One S3 bucket — versioned, public access fully blocked, **no** default
  server-side encryption at the bucket level (encryption happens client-side
  before objects arrive; relying on both is fine defense-in-depth but the
  project's value is demonstrating the client-side layer specifically).
- One KMS customer-managed key with a key policy scoped to a specific IAM role
  (not `"*"` principals).
- IAM role for the gateway service, granted only `kms:GenerateDataKey` and
  `kms:Decrypt` on that specific key, plus scoped S3 put/get.
- CloudTrail trail capturing KMS API calls for audit.

## 5. Data Stored Per Object

```
{
  object_id,
  s3_key,
  iv,                    -- AES-GCM initialization vector
  auth_tag,              -- AES-GCM authentication tag
  encrypted_data_key,     -- KMS-wrapped, safe to store alongside ciphertext
  kms_key_id,             -- which master key/version wrapped it
  created_at
}
```

Only `encrypted_data_key` + KMS decrypt permission can ever reconstruct the
plaintext data key. Nothing plaintext-sensitive is ever persisted.

## 6. Phased Build Plan

**Phase 0 — AWS foundation (Terraform)**
Bucket, KMS key + narrow key policy, IAM role, CloudTrail log group.
*Exit: `terraform apply`/`destroy` clean; KMS key policy has no wildcard
principals.*

**Phase 1 — Core crypto (no AWS calls)**
Pure functions: generate data key, AES-256-GCM encrypt, AES-256-GCM decrypt.
Unit tests: round-trip correctness, tamper detection (flip one ciphertext byte
→ decrypt must fail loudly), wrong-key rejection.
*Exit: all unit tests pass, zero network calls made.*

**Phase 2 — KMS envelope wrapping**
Wire in `GenerateDataKey` and `Decrypt`. Prove the plaintext data key never
touches disk or logs. Revoke IAM decrypt permission and confirm decryption
fails with access-denied, not a silent bad result.
*Exit: encrypt → decrypt round trip works against real KMS; access-denied test
passes.*

**Phase 3 — S3 integration + API**
`POST /objects` and `GET /objects/:id` wired to real S3, storing the schema
from §5.
*Exit: upload via HTTP, confirm the S3 console shows unreadable ciphertext,
download via HTTP returns the original file byte-for-byte.*

**Phase 4 — Key rotation**
Rotate the KMS master key. Confirm files encrypted under the old key version
still decrypt correctly (KMS handles old key versions transparently as long as
they aren't deleted).
*Exit: old and new objects both decrypt successfully after rotation, with no
re-encryption step required.*

**Phase 5 — Demo & audit trail**
Pull CloudTrail/KMS logs showing exactly which principal called `Decrypt` and
when. Package a 60-second demo: upload → show ciphertext in S3 console →
download → show the KMS log entry proving authorized decryption.
*Exit: a live revoke-then-fail, restore-then-succeed demo works end to end.*

## 7. Future Improvements (post-v1)

Roughly in order of value-to-effort:

- **Per-user or per-tenant KMS grants** instead of one shared IAM role — so
  access can be scoped and revoked per person, not just per service.
- **Client-side encryption in the browser** (WebCrypto API) so plaintext never
  reaches the gateway server at all — the gateway would only ever see
  ciphertext, closing the "compromised app server" gap noted in §3.
  This is the natural v2: it upgrades the threat model from "AWS can't read it"
  to "the application backend can't read it either."
- **Automatic KMS key rotation** (AWS supports scheduled annual rotation
  natively) plus a policy for when to force re-encryption of old objects
  under new data keys, versus relying on KMS's transparent old-version support.
- **Searchable metadata without decrypting content** — store non-sensitive
  metadata (filename, size, upload date, course/category for the LU platform)
  unencrypted alongside the encrypted blob, so search/browse doesn't require
  decrypting every candidate object.
- **Envelope re-wrapping on offboarding** — when a person's KMS access is
  revoked, re-wrap active data keys under a key they no longer have access to,
  rather than relying solely on the revoked grant.
- **Integration into the LU platform**: route document uploads through this
  gateway instead of direct S3 PUT, so scanned exams are encrypted at rest
  with access auditable per-download.
- **Multi-region key replication** if the LU platform ever needs
  disaster-recovery across regions — KMS supports multi-region keys natively.
- **Client library / SDK packaging** (`npm install`-able) so the gateway's
  encrypt/decrypt logic is reusable outside this one project.

## 8. Why This Is a Strong Portfolio Piece

- Demonstrates envelope encryption correctly implemented, not just an SDK call
  — the most common junior mistake is conflating "S3 has encryption enabled"
  with "I built encryption," which this project explicitly does not do.
- Produces a live, provable claim ("AWS operators cannot read this data")
  backed by an audit trail, not just a README assertion.
- Has an honest, stated threat model — knowing the boundaries of what a
  security control does and doesn't do is itself a signal of understanding.
- Directly reusable in a second real project (the LU platform), which is more
  convincing than a standalone demo with synthetic data.