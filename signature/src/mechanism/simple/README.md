# Simple Signing

Simple Signing is the first signature that CC supports. Refer to 
[CCv1 Image Security Design](../../../../docs/ccv1_image_security_design.md#image-signing).

## Policy Format

Simple Signing is verified due to the container's policy configuration file.

A Policy Requirement of Simple Signing should be like this

```json
{
    "type": "signedBy",
    "scheme": "simple",
    "keyType": "<KEY-TYPE>",
    "keyData": "<PUBKEY-DATA-IN-BASE64>",
    "keyPath": "<PATH-TO-THE-PUBKEY>",
    "signedIdentity": <JSON-OBJECT>,
},
```

Here, 
* The `type` field must be `signedBy`, showing that this Policy Requirement
needs a signature verification.
* The `scheme` field must be `simple`, showing this signature is Simple Signing.
* The `keyType` field indicates the pubkey's type. Now only `GPGKeys` is supported.
* The `keyData` field includes the pubkey's content in base64.
* The `keyPath` field indicates the pubkey's path. And it **must be** `"/run/image-security/simple_signing/pubkey.gpg"`.
* `signedIdentity` includes a JSON object, refer to [signedIdentity](https://github.com/containers/image/blob/main/docs/containers-policy.json.5.md#signedby) for detail.

**WARNING**: Must specify either `keyData` or `keyPath`, and must not both.

## Work flow

Let's go through the verification logic here.

What we all need to verify a signature are two things:
`signature`, `public key`.

* `public key` is given by the Policy Requirement, either by data
or path.
* Where the `signature` is stored (local path or remote url) is recorded in the `Sigstore Config File`, so we firstly need to create a dir to save `Sigstore Config File`, and then need to get the `Sigstore Config File`.
* After getting the `signature`, we can do the verification.

Let's see what the code do here:

1. `init()` will check and create the directory
* Sigstore Dir: `/run/image-security/simple_signing/sigstore_config`

2. Then the following files will be got from kbs
* Sigstore Configfile: `/run/image-security/simple_signing/sigstore_config/default.yaml`. This file shows where the signatures are stored.
* Gpg public key ring: `/run/image-security/simple_signing/pubkey.gpg`. This key
ring is used to verify signatures.

3. Then access the Sigstore, and gather the signatures related to the image, and
do verifications.