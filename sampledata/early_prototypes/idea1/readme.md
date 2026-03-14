# Source code for samples

## Sample 1 Standalone KAT

A single key attestation token which contains both key and platform claims.

~~~aasvg
 |---------------------------------|
 | .-----------------------------. |
 | | Attester                    | |
 | | --------                    | |
 | | AK Certs                    | |
 | | hwmodel="RATS HSM 9000"     | |
 | | fipsboot=true               | |
 | |                             | |
 | | Key 18                      | |
 | | RSA                         | |
 | '-----------------------------' |
 |                                 |
 |          Root of Trust (RoT)    |
 |---------------------------------|
~~~
{: #fig-arch title="Example of two KATs in a single PAT"}


## Sample 2 PAT containing two KATs

A Platform attestation token which contains two nested key attestation tokens for different keys.

~~~aasvg
 |--------------------------------------|
 | .----------------------------------. |
 | | Attester                         | |
 | | --------                         | |
 | | AK Certs                         | |
 | | hwmodel="RATS HSM 9000"          | |
 | | fipsboot=true                    | |
 | | .-------------.  .-------------. | |
 | | | Key 18      |  | Key 21      | | |
 | | | RSA         |  | ECDH-P256   | | |
 | | '-------------'  '-------------' | |
 | '----------------------------------' |
 |                                      |
 |               Root of Trust (RoT)    |
 |--------------------------------------|
~~~
{: #fig-arch title="Example of two KATs in a single PAT"}


## Sample 3 PAT containing KAT and PAT

A platform attestation token where the root-of-trust environment is `fipsboot=true` and contains one nested KAT and one nested PAT for a sub-environment with `fipsboot=false`.

~~~aasvg
 |-------------------------------------------|
 | .---------------------------------------. |
 | | Attester                              | |
 | | --------                              | |
 | | AK Certs                              | |
 | | hwmodel="RATS HSM 9000"               | |
 | | fipsboot=true                         | |
 | | .----------.  .---------------------. | |
 | | | Key 18   |  | Partition 1         | | | 
 | | | RSA      |  | fipsboot=false      | | |
 | | |          |  | Partition1-RootKey  | | |
 | | |          |  | ECDH-P256           | | |
 | | '----------'  '---------------------' | |
 | '---------------------------------------' |
 |                                           |
 |               Root of Trust (RoT)         |
 |-------------------------------------------|
~~~
{: #fig-arch title="Example of two KATs in a single PAT"}
