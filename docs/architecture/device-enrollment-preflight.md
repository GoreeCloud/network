# Device Enrollment Preflight

## Status

Development foundation only. This document does not authorize device enrollment, key issuance, private-network access, or production activation.

## Purpose

`internal/enrollment` provides a side-effect-free validation boundary for device-owned public enrollment material before any future authenticated enrollment transaction is allowed to mutate GoreeCloud Network state.

The preflight exists to reject malformed or unsupported requests early while keeping authorization, key lifecycle, persistence, routing, and tunnel establishment behind separate authority and acceptance gates.

## Current Development contract

The preflight currently accepts only the native client surfaces represented by this repository:

- Android
- Google TV
- iOS

A request must include a display name, platform identifier, and a non-zero 32-byte base64 public key. Display names are trimmed, bounded to 128 bytes, required to be valid UTF-8, and may not contain control characters or Unicode bidirectional-control formatting characters that could make audit or user-interface presentation ambiguous. Ordinary internationalized names remain supported. Platform identifiers are canonicalized to lowercase. Public keys are decoded and re-encoded into canonical base64 form.

A successful result means only `READY_FOR_AUTHORIZED_ENROLLMENT`: the request is structurally eligible to enter a later authenticated enrollment transaction.

## Explicit non-authority

The preflight does not:

- authenticate a user, administrator, or device through GoreeCloud Identity;
- assign a GoreeCloud Network device ID;
- generate, accept, store, or return private keys;
- issue enrollment secrets, bearer tokens, credentials, or certificates;
- mutate device, resource, policy, route, relay, or tunnel state;
- persist a request or advance the revisioned Network store;
- authorize access to any Network resource;
- establish encrypted connectivity or claim that a device is connected;
- create Privacy Shield, Wardveil Security, Everkeep, Manager, or production-acceptance evidence.

## Required activation gates

A future mutating enrollment flow must remain separate from this validator and must require, at minimum:

1. accepted GoreeCloud Identity authorization for the enrollment operation;
2. a replay-safe and idempotent transaction model;
3. revision-aware durable persistence with rollback-safe failure behavior;
4. explicit device-ID and public-key ownership semantics;
5. auditable lifecycle events without logging enrollment secrets or private key material;
6. independent runtime acceptance before the result can be treated as production-authoritative.

Enrollment must fail closed when any required authority or transaction precondition is unavailable.
