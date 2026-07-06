# BlindVault

# Privacy-Preserving Credential Issuance for the Zcash Ecosystem

## 1. Why This Project Exists

Zcash has spent years making transactions private. Applications built around Zcash, however, still face a different privacy problem that usually gets overlooked: issuing credentials without creating a link between the user requesting the credential and the user redeeming it later.

That situation appears more often than it seems.

An application may want to distribute an airdrop to eligible users, issue one-time faucet claims, grant access to a private service, or anonymously rate-limit an API. In every case the application first determines whether someone is eligible, then later verifies the credential when it is redeemed.

The verification itself is usually straightforward.

Preserving privacy during issuance is not.

Most projects end up choosing one of three options.

They either record enough information to link issuance and redemption, implement blind signatures themselves, or simplify the design by removing the privacy guarantees entirely. None of those are particularly attractive. The first conflicts with the privacy expectations that attract many people to Zcash in the first place. The second requires implementing cryptographic protocols that relatively few developers are comfortable maintaining. The third simply leaves useful applications unexplored.

BlindVault exists because of this problem.

Rather than every project implementing the same cryptographic machinery independently, BlindVault moves that responsibility into reusable infrastructure. Applications remain responsible for deciding *who* is eligible to receive a credential. BlindVault is responsible for issuing, validating and consuming that credential without learning which issued credential is eventually redeemed.

The goal is not to replace application logic.

The goal is to separate application logic from cryptographic protocol implementation.

---

## 2. Project Overview

BlindVault is a middleware service implementing privacy-preserving credential issuance using BLS12-381 blind signatures together with DLEQ proofs.

An application authenticates a user. Could be a CAPTCHA, proof of ownership of a shielded address, KYC, membership verification or any other eligibility check. Once eligibility has been established, the application requests a blind signature from BlindVault.

Because the request is blinded before signing, BlindVault never learns the final credential that will later be presented for redemption.

When the user eventually redeems that credential, BlindVault verifies three things:

* the signature is valid,
* the credential belongs to the expected credential class,
* and it has not been redeemed previously.

If all three conditions hold, the credential is consumed and cannot be used again.

BlindVault intentionally stays out of the application's business logic.

It does not know why a credential is being issued.

It does not know what reward is attached to it.

It does not decide who is eligible.

Those decisions remain entirely under application control.

Instead, BlindVault provides a narrowly scoped service that applications can depend on whenever they need unlinkable credential issuance.

---

## 3. Design Goals

BlindVault was designed around a small number of practical goals.

### Privacy by default

The service should never learn enough information to correlate issuance with redemption. Applications determine eligibility, while the middleware only performs cryptographic operations required for issuance and verification.

### Reusable infrastructure

The cryptography should not need to be rewritten every time another project wants anonymous credentials. Integrating the service should require calling an HTTP API rather than understanding blind signature protocols.

### Operational simplicity

Running BlindVault should not require specialized infrastructure. A standard deployment consists of the service itself together with a Redis instance for replay protection. Everything else is self-contained.

### Clear security boundaries

The service intentionally performs one job.

It issues credentials.

It verifies credentials.

It prevents replay.

Authorization, user accounts, payments, KYC, and application-specific policy remain outside the system.

Keeping those responsibilities separate makes both the application and BlindVault easier to reason about and easier to audit.

## 4. System Architecture

BlindVault separates application logic from credential issuance.

The application remains responsible for determining whether a user should receive a credential. BlindVault only performs the cryptographic operations required to issue, verify and consume that credential.

This separation keeps the service intentionally small. It does not need to understand application-specific concepts such as accounts, balances, membership or payments. As long as the application can answer "is this user eligible?", BlindVault can issue an unlinkable credential.

A typical flow looks like this:

```
Application
      │
      │ Verify eligibility
      ▼
BlindVault
      │
      │ Issue blind signature
      ▼
     User
      │
      │ Unblind locally
      ▼
 Anonymous Credential
      │
      │ Redeem
      ▼
BlindVault
      │
      │ Verify signature
      │ Check replay
      ▼
Application
```

Only the application knows why the credential exists.

Only the user knows the final unblinded credential.

BlindVault never observes enough information to correlate issuance with redemption.

---

## 5. Cryptographic Design

BlindVault implements blind signatures over the BLS12-381 pairing-friendly curve together with Discrete Logarithm Equality (DLEQ) proofs.

The cryptographic protocol provides three properties that the service relies on.

* The server can sign a blinded message without learning the original message.
* The client can prove possession of a valid signature after unblinding.
* The client can verify that the signature was produced using the expected signing key.

Those guarantees allow applications to issue credentials without introducing a persistent link between issuance and redemption.

The cryptography is intentionally isolated behind a small API. Applications do not need to understand pairings, scalar arithmetic or proof generation. They only request credentials and verify the result.

---

### Credential Classes

A single signing key for every credential would create unnecessary coupling between unrelated applications.

Instead, every credential belongs to a credential class.

Examples include:

* `airdrop_2026`
* `faucet`
* `event_registration`
* `tier_gold`

Credential classes provide cryptographic namespace isolation.

A credential issued for one class cannot be redeemed for another because every class derives an independent signing key.

This prevents accidental reuse across applications and allows applications to revoke or rotate individual namespaces without affecting every deployed credential.

Applications are free to define credential classes that best match their own domain.

BlindVault treats them as opaque identifiers.

---

### Deterministic Key Derivation

BlindVault does not store a separate private key for every credential class.

Instead, all signing keys are derived from a single master secret using HKDF with explicit domain separation.

Conceptually:

```
Master Secret
       │
       ├─────────────► airdrop_2026
       │
       ├─────────────► faucet
       │
       ├─────────────► tier_gold
       │
       └─────────────► event_registration
```

This design has several practical advantages.

New credential classes can be created without generating or storing additional keys.

Key management remains simple because only the master secret requires long-term protection.

Different credential classes remain cryptographically isolated even though they originate from the same root secret.

The derivation also includes an epoch value, allowing future key rotation without changing the overall architecture.

---

### DLEQ Proofs

Blind signatures alone prove that a signature is mathematically valid.

They do not prove that the server used the correct derived signing key.

BlindVault therefore returns a DLEQ proof together with every issued signature.

The proof allows the client to verify that the blind signature was produced using the public key corresponding to the requested credential class.

Without this proof, a faulty or malicious server could potentially sign using a different key while still returning an apparently valid response.

Adding DLEQ proofs makes key substitution detectable by the client.

Verification happens entirely on the client side and requires no additional interaction with the server.

---

## 6. Replay Protection

Anonymous credentials are only useful if they cannot be reused indefinitely.

BlindVault prevents replay using deterministic nullifiers.

During redemption, the service derives a nullifier from the credential together with the credential class and signing epoch.

The resulting value uniquely identifies a redeemed credential without revealing the original blinded message.

The nullifier is inserted atomically into the configured storage backend.

If the insertion succeeds, redemption continues.

If the nullifier already exists, the request is rejected as a replay.

This design intentionally avoids storing the credential itself.

Only the nullifier is retained.

As a result, replay protection does not require maintaining a database of every issued credential or introducing new information that could weaken unlinkability.

The default implementation uses Redis because atomic insertion is sufficient for this workload, but the storage layer is abstracted behind an interface. Other implementations can be added without changing the cryptographic protocol.

---

## 7. Security Model

BlindVault is designed around a deliberately narrow trust boundary.

The service assumes that the application correctly determines user eligibility before requesting credential issuance.

It does not attempt to verify identity, ownership of assets or application-specific policy.

Within those assumptions, BlindVault guarantees:

* unlinkability between issuance and redemption,
* cryptographic verification of issued credentials,
* detection of replay attempts,
* namespace isolation between credential classes,
* verification that signatures originate from the expected derived key.

BlindVault does **not** attempt to solve problems outside its scope.

It is not an authentication provider.

It is not a wallet.

It is not an authorization framework.

It does not replace application-level security.

Keeping those responsibilities separate reduces complexity and makes the service easier to audit and reason about.

## 8. Why This Matters for the Zcash Ecosystem

BlindVault is not tied to a single application.

It solves a recurring problem that appears whenever a project needs to issue something anonymously and verify it later.

The details of the application change, but the underlying cryptographic workflow is usually the same:

1. Determine whether someone is eligible.
2. Issue a credential.
3. Allow that credential to be redeemed exactly once.
4. Avoid creating a link between issuance and redemption.

Without reusable infrastructure, every project that needs this workflow either implements blind signatures independently or compromises on privacy.

BlindVault provides a common implementation that applications can integrate instead of rebuilding.

The intention is not to replace application logic.

The intention is to make privacy-preserving credential issuance as reusable as authentication middleware or database drivers.

---

### Example Integrations

The following examples are not features built into BlindVault.

They are examples of applications that can use the service without modifying its cryptographic protocol.

#### Anonymous Community Rewards

A community wants to distribute rewards to members who satisfy some eligibility requirement.

Eligibility may come from forum participation, governance voting, shielded balance proofs or another verification process.

Once eligibility has been established, the application requests a blind credential.

Later, the user redeems that credential anonymously.

The application can verify that the credential is valid without learning which eligible participant redeemed it.

---

#### Privacy-Preserving Faucets

Faucets frequently need to limit abuse while remaining accessible.

Today this often means recording identifiers that create unnecessary linkage between requests.

With BlindVault, a faucet verifies that a user satisfies its admission policy, issues a credential and accepts exactly one redemption for that credential.

The replay protection happens independently of user identity.

---

#### Anonymous Access Control

Some services only need to answer a simple question:

"Is this user authorized?"

They do not necessarily need to know who the user is.

BlindVault allows an external system to perform identity verification once, issue a credential and later verify possession of that credential without requiring identity to be presented again.

The authorization policy remains outside BlindVault.

Only credential issuance and verification are shared.

---

#### Anonymous Rate Limiting

Some APIs need to distinguish legitimate users from abusive traffic without permanently identifying clients.

Applications can issue short-lived credentials that allow access to protected endpoints.

Each credential can be consumed according to the application's policy while remaining unlinkable to the original issuance request.

---

### Why Middleware Instead of a Library?

One design decision made early in the project was to implement BlindVault as a standalone service rather than a Go package.

That choice was intentional.

Many applications that could benefit from anonymous credentials are not written in Go.

Others consist of multiple services written in different languages.

An HTTP API allows every service to use the same implementation regardless of programming language.

It also centralizes operational concerns such as metrics, logging, replay protection and key management.

Applications only interact with a small set of endpoints instead of embedding cryptographic code directly into their own codebases.

Keeping the cryptography in one service also simplifies upgrades.

Bug fixes, security improvements and protocol changes can be deployed once instead of requiring every application to update its own implementation independently.

---

## 9. Implementation Status

BlindVault is not a research proposal.

The core system has already been implemented.

The completed work includes:

* BLS12-381 blind signature implementation
* DLEQ proof generation and verification
* Deterministic key derivation using HKDF
* Credential namespace isolation
* Replay protection using deterministic nullifiers
* REST API for credential issuance and consumption
* JWT authentication for issuance endpoints
* Redis-backed nullifier storage
* In-memory backend for testing
* Structured logging with request identifiers
* Prometheus metrics
* Docker deployment
* Docker Compose environment
* End-to-end integration tests
* Unit and integration test suites
* GitHub Actions continuous integration
* Cryptographic specification
* API documentation
* Deployment documentation
* Cryptographic test vectors

The implementation was developed with production deployment in mind rather than as a proof of concept.

Testing, deployment and operational tooling were developed alongside the cryptographic implementation because all three are required before other projects can realistically depend on the service.

---

## 10. Engineering Decisions

Several implementation decisions were made to reduce operational complexity without weakening the security model.

The service keeps persistent state to a minimum.

Only replay protection requires storage.

Credential verification itself remains stateless.

Key management is similarly simplified.

Instead of maintaining a database of signing keys, BlindVault derives signing keys deterministically from a single protected master secret.

This removes an entire class of operational problems while allowing independent credential namespaces and future key rotation.

The codebase is organized into separate packages for cryptography, storage, service logic and HTTP transport.

Each layer exposes a small interface to the next.

That separation keeps the cryptographic implementation independent of deployment concerns and allows individual components to be tested in isolation.

From the beginning, the project was developed with reproducibility in mind.

Docker images, automated testing, CI workflows and deployment documentation were treated as part of the deliverable rather than work to be added after the implementation was finished.

The objective was to produce software that another developer could evaluate, run locally and integrate without needing to reverse engineer the design.

## 11. Future Work

BlindVault already provides the functionality required for anonymous credential issuance.

Future development will focus on improving interoperability and making the service easier to integrate into privacy-preserving applications.

Areas of interest include:

* integration examples for common Zcash application patterns,
* additional storage backends,
* expanded operational tooling,
* stronger observability and monitoring,
* support for additional credential formats where they complement the existing protocol,
* improvements based on community review and external security feedback.

Future work will be guided by practical adoption rather than adding features for their own sake.

---

## 12. Closing Remarks

Privacy-preserving payments are only one part of a privacy-preserving ecosystem.

Applications also need a way to issue credentials without creating unnecessary links between users and their future actions.

BlindVault addresses that problem by separating eligibility decisions from credential issuance and providing a reusable implementation of blind signature-based credentials.

The project does not attempt to replace application logic or define new privacy protocols.

Instead, it provides a focused service that applications can build upon whenever anonymous credential issuance is required.

Because the implementation is already complete, developers can evaluate the code, inspect the cryptographic specification, review the tests and integrate the service directly into their own applications.

The requested funding supports reusable infrastructure that is intended to remain available to the broader Zcash ecosystem rather than serving a single application.

If BlindVault succeeds, the primary outcome should not be that one more project uses blind signatures.

It should be that future Zcash applications no longer need to implement this component themselves.

They can focus on solving their own problems while depending on a common, open-source implementation of privacy-preserving credential issuance.

## Appendix A — Threat Model

BlindVault is designed to provide unlinkable credential issuance under a clearly defined set of assumptions. This appendix describes those assumptions, the adversarial model and the security properties provided by the protocol.

The purpose of this section is not to claim that BlindVault solves every privacy problem. Instead, it defines exactly what the service is responsible for and what remains the responsibility of the integrating application.

### Trust Assumptions

BlindVault assumes that applications correctly determine whether a user is eligible before requesting credential issuance.

Eligibility itself is outside the scope of the protocol. It may be based on CAPTCHA, proof of ownership of a shielded address, KYC, governance participation or any other policy chosen by the integrating application.

BlindVault also assumes that the server protects the master signing secret. If the master secret is compromised, new credentials can be forged until keys are rotated. Previously consumed credentials remain protected by the replay mechanism, but cryptographic authenticity can no longer be guaranteed.

The protocol further assumes that the cryptographic primitives used by the implementation remain secure, including the hardness assumptions underlying BLS12-381, HKDF-SHA256 and SHA-256.

### Adversary Model

BlindVault considers adversaries capable of observing network traffic, submitting arbitrary protocol messages, replaying previously observed requests and attempting to forge credentials.

An attacker may interact with the service as an ordinary client and may attempt to redeem modified or previously consumed credentials.

BlindVault does not assume honest clients.

All protocol inputs are treated as untrusted.

The implementation validates every request before cryptographic verification proceeds.

### Security Goals

Within these assumptions, BlindVault aims to provide:

* unlinkability between credential issuance and redemption,
* cryptographic authenticity of issued credentials,
* replay detection,
* namespace isolation between credential classes,
* verification that signatures were generated using the expected derived signing key.

Applications inherit these guarantees without needing to implement blind signature protocols themselves.

### Out of Scope

BlindVault intentionally does not attempt to solve:

* user authentication,
* Sybil resistance,
* spam prevention,
* application authorization,
* wallet security,
* identity management,
* private network communication.

Applications remain responsible for these concerns.

## Appendix B — Security Properties

BlindVault was designed around a small number of explicit security properties.

### Unlinkability

After a credential has been unblinded, the issuing server cannot determine which issued credential corresponds to a later redemption.

This property follows directly from the blind signature protocol.

As long as the server does not possess external identifying information supplied by the application, issuance and redemption remain cryptographically unlinkable.

---

### Replay Resistance

Every redeemed credential produces a deterministic nullifier.

The first redemption stores that nullifier.

Subsequent attempts produce the same value and are rejected.

Replay detection therefore requires only storage of consumed nullifiers rather than every issued credential.

---

### Namespace Isolation

Credential classes derive independent signing keys.

Compromise or revocation of one namespace does not affect unrelated credential classes.

Applications can therefore separate credentials according to their own security policies.

---

### Public Verifiability

Clients verify both the blind signature and the accompanying DLEQ proof.

A malicious or faulty server cannot silently substitute another signing key without detection.

Verification occurs entirely client-side and requires no additional trust assumptions.

---

### Minimal Persistent State

BlindVault intentionally stores as little information as possible.

Replay protection requires only consumed nullifiers.

Issued credentials are never stored.

This minimizes operational complexity while reducing the amount of information available if storage is compromised.

## Appendix C — Protocol Overview

The protocol consists of two independent phases.

### Credential Issuance

1. The application determines whether the user satisfies its eligibility policy.
2. The client generates a blinded message.
3. The application requests credential issuance for a specific credential class.
4. BlindVault derives the signing key for that class.
5. BlindVault signs the blinded message.
6. BlindVault produces a DLEQ proof.
7. The client verifies the proof.
8. The client unblinds the signature locally.

At no point does BlindVault observe the final credential.

---

### Credential Redemption

1. The client submits the credential.
2. BlindVault derives the signing key for the requested credential class.
3. The signature is verified.
4. A deterministic nullifier is computed.
5. The nullifier store performs an atomic insertion.
6. If insertion succeeds, redemption succeeds.
7. Otherwise the credential has already been consumed.

The protocol requires only one persistent operation during redemption.

## Appendix D — Known Limitations

BlindVault deliberately limits its scope.

Several limitations are therefore expected.

BlindVault does not hide network metadata.

Applications requiring network-level privacy should deploy behind anonymity networks such as Tor or other suitable infrastructure.

BlindVault cannot prevent applications from collecting identifying information before requesting credential issuance.

Privacy during credential redemption does not compensate for privacy lost during application-specific onboarding.

Replay protection depends on the availability and correctness of the configured storage backend.

Deployments should therefore use highly available storage appropriate for their operational requirements.

The protocol currently focuses on one-time anonymous credentials.

More expressive credential systems, such as selectively disclosable or attribute-based credentials, remain future work.

Finally, BlindVault has been engineered with correctness and testability as primary goals.

Like any security-critical software, it benefits from external review and independent cryptographic audit before deployment in high-value environments.

## Appendix E — Design Evolution

BlindVault did not begin with its current architecture.

Many parts of the system changed as implementation progressed and practical constraints became clearer. The final design is the result of simplifying the system while improving its security properties and making it easier to operate.

This appendix documents some of the more significant design decisions.

---

### From `key_id` to `credential_class`

Early versions of the protocol identified signing keys using a `key_id`.

While technically correct, the name suggested that applications were expected to manage individual cryptographic keys.

That was never the intention.

Applications do not care which private key signs a credential.

They care about *what the credential represents*.

Renaming the field to `credential_class` better reflects the role it plays within the protocol.

A class identifies a namespace such as `faucet`, `airdrop_2026` or `tier_gold`.

BlindVault derives the appropriate signing key internally.

Applications never interact with signing keys directly.

This change made the API easier to understand while more accurately representing the protocol.

---

### Credential Classes Became Cryptographic Namespaces

Initially, credential classes were introduced primarily to organize credentials.

As development progressed they became an important security boundary.

Every credential class derives an independent signing key from the master secret.

As a result:

* credentials cannot be redeemed across unrelated applications,
* namespaces can be rotated independently,
* compromise of one namespace does not require replacing every credential in the system.

Treating credential classes as cryptographic namespaces simplified several other parts of the implementation and removed the need for multiple independently managed signing keys.

---

### Deterministic Key Derivation Replaced Key Storage

One early approach considered storing independent signing keys for every credential class.

Although straightforward, it introduced unnecessary operational complexity.

Creating a new credential class required generating and protecting another long-term private key.

Recovery procedures became more complicated.

Backups became more complicated.

Key rotation became more complicated.

Using HKDF to derive signing keys from a protected master secret removed those operational concerns while preserving cryptographic isolation between credential classes.

The implementation now manages one long-term secret instead of an expanding collection of unrelated keys.

---

### DLEQ Proofs Became a Required Part of Issuance

A valid blind signature alone does not prove that the server used the expected signing key.

Without an additional proof, a faulty implementation could sign using an unintended derived key while still returning a mathematically valid signature.

For that reason DLEQ proofs became mandatory.

Every issued credential now includes a proof that binds the blind signature to the expected public key for the requested credential class.

This provides stronger guarantees to clients without introducing additional network round trips.

---

### Replay Protection Was Designed Around Minimal State

Anonymous credentials require replay protection, but replay protection often encourages storing additional information about users or issued credentials.

BlindVault intentionally avoids that approach.

Only deterministic nullifiers are stored.

Issued credentials are never recorded.

This keeps persistent state small while preserving unlinkability between issuance and redemption.

The storage backend therefore becomes responsible only for answering one question:

*"Has this credential already been redeemed?"*

Nothing more.

---

### Cryptography Was Separated From Transport

Early during implementation it became clear that cryptographic correctness should not depend on HTTP handlers, JSON serialization or storage backends.

The project was therefore organized into independent packages.

The cryptographic implementation knows nothing about HTTP.

The HTTP layer knows nothing about elliptic curve arithmetic.

Storage implementations know nothing about blind signatures.

Each layer communicates through small interfaces.

Besides improving testability, this organization makes it easier to audit security-critical code because protocol logic remains isolated from operational concerns.

---

### Storage Became an Interface

Replay protection is conceptually simple.

Store a nullifier once.

Reject it if it already exists.

Rather than binding the implementation to Redis, BlindVault defines a storage interface that expresses only the operations required by the protocol.

Redis became the default implementation because it provides efficient atomic operations suitable for replay detection.

Other implementations can be introduced without changing the cryptographic protocol.

Keeping storage behind a small interface also makes testing significantly easier.

Unit tests can use an in-memory implementation while production deployments use Redis.

---

## Production Concerns Were Treated as Core Features

The original objective was to implement blind signatures.

During development it became clear that reusable infrastructure requires considerably more than a working cryptographic protocol.

Testing, documentation, deployment tooling, metrics, structured logging and continuous integration were developed alongside the implementation rather than being postponed until later.

---

## Scope Was Intentionally Limited

One recurring design decision throughout development was deciding what *not* to build.

BlindVault does not manage user accounts.

It does not define eligibility policies.

It does not perform identity verification.

It does not replace application authorization.

Restricting the project to credential issuance and verification keeps the implementation easier to understand, easier to audit and easier to integrate into existing systems.

The objective is to provide one component that applications can rely on rather than another framework they must adapt their architecture around.

---

## Looking Forward

The current architecture provides a stable foundation for anonymous credential issuance.

Future work is expected to focus on interoperability rather than fundamental protocol redesign.

Potential areas include:

* integration with additional privacy-preserving protocols,
* alternative storage implementations,
* expanded deployment options,
* external cryptographic review,
* additional credential formats where they complement the existing design.

The underlying architecture was designed with these extensions in mind, but they remain intentionally separate from the core protocol so that BlindVault can remain small, predictable and easy to reason about.

