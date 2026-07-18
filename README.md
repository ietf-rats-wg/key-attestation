# Key Attestation

This is the working area for the individual Internet-Draft, "Key Attestation".

* [Editor's Copy](https://ietf-rats-wg.github.io/key-attestation/#go.draft-ietf-rats-pkix-key-attestation.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-ietf-rats-pkix-key-attestation)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-ounsworth-rats-key-attestation)
* [Compare Editor's Copy to Individual Draft](https://ietf-rats-wg.github.io/key-attestation/#go.draft-ietf-rats-pkix-key-attestation.diff)


## Contributing

See the
[guidelines for contributions](https://github.com/ietf-rats-wg/key-attestation/blob/main/CONTRIBUTING.md).

Contributions can be made by creating pull requests.
The GitHub interface supports creating pull requests using the Edit (✏) button.


## Command Line Usage

Formatted text and HTML versions of the draft can be built using `make`.

```sh
$ make
```

Command line usage requires that you have the necessary software installed.  See
[the instructions](https://github.com/martinthomson/i-d-template/blob/main/doc/SETUP.md).

## Directory Structure

- **draft-ietf-rats-pkix-key-attestation.md** : File that contains the text of this specification.
- **Pkix-Key-Attest-2025.asn** : File that contains the ASN.1 module described by this specification.
- **go-src** : Directory that contains source code for a goLang Verifier based on this specification.
- **sampledata** : Directory that contains examples of generated Evidence. These examples are created by the scripts found in the directory `src`.
- **src** : Directory that contains Python scripts relating to the ASN.1 module offered by this specification. These scripts provide operations such as validating evidence or generating sample data. More information can be found in the `readme.md` file.
- **src2** : Directory that contains Interim Python scripts used to migrate to latest ASN.1 module.
- **tools** : Directory that contains scripts to automate some testing.
