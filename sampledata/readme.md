# Source code for samples

## Sample 1 Standalone KAT

A single key attestation token which contains both key and platform claims.

## Sample 2 PAT containing two KATs

A Platform attestation token which contains two nested key attestation tokens for different keys.

## Sample 3 PAT containing KAT and PAT

A platform attestation token where the root-of-trust environment is `fipsboot=true` and contains one nested KAT and one nested PAT for a sub-environment with `fipsboot=false`.