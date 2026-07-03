# Spec Matrix

Target: `draft-irtf-cfrg-cpace-21`, published April 23, 2026.

Audit: the original matrix was reviewed against implementation commit `2e09774f171dde8c62763d6e35a258b0fef88801` on 2026-05-08 and later refreshed for the inherited Ristretto implementation at `f7efa6a963a954952b1ecad3f46530f13799fe89`. This X25519 fork changes protocol code, dependency shape, vectors, and invalid-share behavior after that inherited evidence baseline; refresh the security/spec audit before making release-current claims.

| Draft requirement | Implementation | Tests |
| --- | --- | --- |
| Use `transcript_ir(Ya,ADa,Yb,ADb)` in initiator-responder mode | `newIRTranscript` / `irTranscript` in `transcript.go`; symmetric/OC transcript helpers are test-vector-only via `testTranscriptOC` in `strings_test.go` | `TestStringUtilitiesDraftVectors`, `TestIRTranscriptDraftVectorFlow`, `TestX25519Draft21Vectors` |
| Use LEB128 length-value encoding for `prepend_len` and `lv_cat` | `length_value.go`, `framing.go` | `TestStringUtilitiesDraftVectors`, `TestLengthValueEncodingBoundaries`, malformed parser tests |
| `generator_string(DSI,PRS,CI,sid,s_in_bytes)` with SHA-512 block size 128 | `generatorString` | `TestX25519Draft21Vectors` |
| `G_X25519.DSI = "CPace255"` | `dsiX25519` | `TestX25519Draft21Vectors` |
| Hash generator string to 64 bytes, use the first 32 bytes, and map to Curve25519 with Elligator2 | `calculateGenerator`, `elligator2Curve25519` | `TestEmbeddedDraftGeneratorJSON`, `TestX25519Draft21Vectors` |
| Sample X25519 scalars as 32 random bytes, with X25519 clamping applied by scalar multiplication | `sampleScalar`, `x25519ScalarMult` | `TestScalarSamplingReturnsDraftX25519Bytes`, `TestScalarSamplingWrapsRandomnessReadFailure`, public exchange tests |
| `scalar_mult_vfy` aborts on decode failure or neutral output | `scalarMultVFY` enforces the exact 32-byte share length, runs the X25519 ladder, and returns nil plus an `ErrAbort`-wrapped error if the output is all zero. The nil-plus-error convention is an intentional internal-only divergence from the draft's function-level neutral-element return, preserving identical abort behavior (ADR-0003). | `TestScalarMultVFYDraftInvalidVectors`, `TestScalarMultVFYLowOrderIdentity`, embedded X25519 low-order JSON fixture |
| Compute ISK from `lv_cat(DSI_ISK,sid,K)||transcript_ir(...)` | `deriveISK` | `TestX25519Draft21Vectors`; embedded X25519/SHA-512 JSON fixture re-encoded from the draft appendix and hash-pinned |
| Add explicit key confirmation with MAC key derived from ISK | `confirmationTag`, `Initiator.Finish`, `Responder.Finish`; tags remain draft-compatible with no package-added role labels | confirmed exchange and mismatch tests; `TestEmbeddedDraftConfirmationTagGoldens`, `TestX25519Draft21Vectors`, `TestCoreDraft21Vectors` |
| Integrate initiator and responder identifiers into CI with role binding | `buildCI` | mismatch tests; CI format documented as package-owned |
| Abort on invalid/weak points | `Respond` prevalidates message A shares with a fixed scalar before responder generator derivation or scalar sampling, then uses the real responder scalar for Diffie-Hellman; `Initiator.Finish` applies `scalarMultVFY` to responder shares. X25519 low-order shares wrap `ErrAbort` plus `ErrPeerShareIdentity` with role context; malformed wire lengths remain `ErrMessage`. | `TestProtocolAbortsOnLowOrderX25519Share`, `TestResponderPrevalidatesInvalidInitiatorShareBeforeRandomness`, `TestInitiatorAbortsOnInvalidResponderShare`, `TestPeerShareErrorsWrapErrAbort`, `TestPeerShareIdentityRejection` |

Package-owned profile and extensions:

| Package behavior | Status | Tests |
| --- | --- | --- |
| `cpace-go` CI construction from draft version, suite, role labels, identities, and context | Package profile over draft-21 CI input, not a generic raw-CI interface | transcript-locking mismatch tests |
| Binary wire framing with format byte `0xc1`, suite byte, role byte, and draft LEB128 fields | Package-owned application framing | `TestWireFormatPrefixByte`, parser tests |
| Per-field size caps for package-owned input and wire fields | Password and IDs 4 KiB; context and session ID 1 KiB; local associated data 64 KiB; public shares and tags exact-size decoded | `TestInputFieldSizeLimits`, `TestMessageFramingCatalogueRejectsFieldLimits`, `TestMessageFramingCatalogueOwnsFieldLengthAcceptance` |
| `Session.Export` using HKDF-SHA512 over confirmed ISK | Package extension following the draft recommendation to process ISK with a KDF | `TestConfirmedExchangeAndExport`, example |
| `Session.TranscriptID` as draft `CPaceSidOutput` | Public accessor for draft optional session identifier output; not a complete channel binding for outer negotiation | vector and exchange tests |

Known gaps before a production release:

- independent cryptographic review
- external review of package-owned message framing, CI, and profile choices
