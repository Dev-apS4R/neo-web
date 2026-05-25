# Security Specification: Neo-Platform Access Control (TDD Spec)

This document outlines the security architecture, invariants, and threat vectors for the "Neo" dark-mode profile platform. Access control relies on Zero-Trust Attribute-Based Access Control (ABAC) on Firebase Firestore.

## 1. Core Invariants

1. **Owner-Private Singularity**: Every user's private data (at path `/users/{userId}/private/info`) is strictly readable and writable *only* by the authenticated user whose `request.auth.uid` matches the document's `{userId}` path parameter.
2. **Read-verified Isolation**: Public profiles are read-accessible by any signed-in user, but modifications require `request.auth.token.email_verified == true`.
3. **No-Self-Verified State**: Users *cannot* manually assert or update `emailVerified` true in their private records. It must match the authentication credential `request.auth.token.email_verified`.
4. **Id Integrity (Sanitization)**: All document IDs and fields must match strict character sets to prevent path-traversal or character-poisoning attacks.
5. **Growth Bounding**: All string parameters must be size-capped to prevent "Denial of Wallet" size bloat exploits.

---

## 2. The "Dirty Dozen" Malicious Payloads

The following payloads represent illegal database writes designed to bypass authentication, poison profiles, or escalate privileges.

### Payload 1: ID Impersonation on Profile Creation
*   **Target Path**: `/users/alice_user_id` (Written by authenticated user Bob, `request.auth.uid == "bob_user_id"`)
*   **Rogue Objective**: Hijack other users' handles or profiles.
*   **Payload**:
    ```json
    {
      "username": "alice",
      "displayName": "Alice Smith",
      "bio": "I am bob in disguise"
    }
    ```
*   **Required Outcome**: `PERMISSION_DENIED` (UID in path does not match `request.auth.uid`).

### Payload 2: Ghost Field Injection (Shadow Update)
*   **Target Path**: `/users/bob_user_id` (by Bob)
*   **Rogue Objective**: Inject undocumented fields to activate legacy or hidden application behaviors.
*   **Payload**:
    ```json
    {
      "username": "bob",
      "displayName": "Bob Builder",
      "bio": "Can we build it?",
      "isPlatformAdmin": true,
      "unauthorizedBackdoor": "granted"
    }
    ```
*   **Required Outcome**: `PERMISSION_DENIED` (strictly checked via `affectedKeys().hasOnly()` or exact key size limit).

### Payload 3: Email Verification State Spoofing
*   **Target Path**: `/users/bob_user_id/private/info` (by Bob, but without real email verification)
*   **Rogue Objective**: Manually spoof the `emailVerified = true` database state to skip verification gates.
*   **Payload**:
    ```json
    {
      "email": "bob@unverified.com",
      "emailVerified": true,
      "createdAt": "request.time"
    }
    ```
*   **Required Outcome**: `PERMISSION_DENIED` (Value of `incoming().emailVerified` must match `request.auth.token.email_verified`).

### Payload 4: Immutable Resetting (Chronological Poisoning)
*   **Target Path**: `/users/bob_user_id/private/info` (by Bob on Update)
*   **Rogue Objective**: Modify account history/age to spoof "early adopter" status.
*   **Payload**:
    ```json
    {
      "email": "bob@real.com",
      "emailVerified": true,
      "createdAt": "2020-01-01T00:00:00Z"
    }
    ```
*   **Required Outcome**: `PERMISSION_DENIED` (Changes of `createdAt` must be restricted; `incoming().createdAt == existing().createdAt`).

### Payload 5: Buffer Overflow Profile (Denial of Wallet)
*   **Target Path**: `/users/bob_user_id`
*   **Rogue Objective**: Store massive string payloads (e.g. 10MB) in fields to cause heavy transfer overhead and bankrupt project storage.
*   **Payload**:
    ```json
    {
      "username": "bob",
      "displayName": "Bob",
      "bio": "A" (repeated 500,000 times)
    }
    ```
*   **Required Outcome**: `PERMISSION_DENIED` (`incoming().bio.size() <= 300` check fails).

### Payload 6: Path Poisoning ID Injection
*   **Target Path**: `/users/admin..%2F..%2Fsys_config` (by authenticated user)
*   **Rogue Objective**: Write document with relative paths to escape `/users` directory.
*   **Payload**:
    ```json
    {
      "username": "injected",
      "displayName": "Malicious"
    }
    ```
*   **Required Outcome**: `PERMISSION_DENIED` (Document ID does not match safety regex `^[a-zA-Z0-9_\-]+$`).

### Payload 7: Verification Bystander Bypass
*   **Target Path**: `/users/bob_user_id` (Create or update)
*   **Rogue Objective**: Set up and customize a public profile profile without completing verification.
*   **Payload**:
    ```json
    {
      "username": "bob",
      "displayName": "Bob Builder"
    }
    ```
*   **Required Conditions**: Requesting user `request.auth.token.email_verified` is `false`.
*   **Required Outcome**: `PERMISSION_DENIED`.

### Payload 8: Cross-Tenant PII Read
*   **Target Path**: `/users/alice_user_id/private/info` (Read request by Bob)
*   **Rogue Objective**: Leak another user's verified email.
*   **Payload**: `GetDocument` call on Bob's client targeting Alice's private subcollection.
*   **Required Outcome**: `PERMISSION_DENIED` (Read block does not match `request.auth.uid == userId`).

### Payload 9: List-Query Scraping (Relational Leakage)
*   **Target Path**: `/users/{userId}/private/info` (List request aiming to dump all users' emails)
*   **Rogue Objective**: List query on all private directories.
*   **Payload**: `db.collectionGroup("private")` or `db.collection("users/alice_user_id/private")` listing from unrelated user.
*   **Required Outcome**: `PERMISSION_DENIED`.

### Payload 10: Array Flood Attack
*   **Target Path**: `/users/bob_user_id`
*   **Rogue Objective**: Write an infinite array of skills or links to deplete query bandwidth.
*   **Payload**:
    ```json
    {
      "username": "bob",
      "displayName": "Bob Builder",
      "skills": ["JavaScript", ...] (repeated 1000 times)
    }
    ```
*   **Required Outcome**: `PERMISSION_DENIED` (`incoming().skills.size() <= 10` criteria fails).

### Payload 11: Spoofed Email Domain Insertion
*   **Target Path**: `/users/bob_user_id/private/info`
*   **Rogue Objective**: Write email in profile document that diverges from the authentic login token email.
*   **Payload**:
    ```json
    {
      "email": "president@whitehouse.gov",
      "emailVerified": true,
      "createdAt": "request.time"
    }
    ```
*   **Required Outcome**: `PERMISSION_DENIED` (`incoming().email == request.auth.token.email` validation fails).

### Payload 12: Admin Claim Self-Assignment
*   **Target Path**: `/users/bob_user_id`
*   **Rogue Objective**: Append role details to public records.
*   **Payload**:
    ```json
    {
      "username": "bob",
      "displayName": "Bob",
      "role": "admin"
    }
    ```
*   **Required Outcome**: `PERMISSION_DENIED` (Validation helper rejects keys outside exact spec or allows changes exclusively of designated profile attributes).

---

## 3. Test Assertion Plan

We require all 12 scenarios to consistently respond with `PERMISSION_DENIED`. Any rule changes will be validated against this structural specification sheet.
