# Contract corrections from 2026-07-07 through 2026-08-19

This record preserves correction history removed from the current contracts. The current contract files state only the rule that the code enforces.

## 2026-07-07 consent decision correction

The earlier approval text denied only when `approved === false`. An absent value therefore reached the approval path. The corrected rule approves only exact `true`; every other value denies. The UI and adapter work originally carried the internal label `Phase 3`, and the defect was tracked as fix 5.

## 2026-08-19 malformed consent-cookie correction

An unguarded `decodeURIComponent` call let a malformed percent escape leave `Bridge.handleApprove` as a raw `URIError`, which became `500 internal_error`. The corrected path maps the malformed cookie credential to direct `400 invalid_consent`.

## 2026-08-19 issuer spelling decision

`createBridgeConfig` stores and emits the exact validated `issuer` spelling instead of a separately normalized copy. A normalized copy could mint tokens under an issuer string the deployer did not configure. The local HTTP example was previously described by the internal label `Phase 4`.
