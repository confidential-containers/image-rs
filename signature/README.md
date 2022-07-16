# Signature Module for Image-rs

This is the signature module for image-rs. In fact, signature verification
is included in the policy processing.

## How is signature verification working?

Up to now, all signature verification in image-rs happens due to
the image security [policy](https://github.com/confidential-containers/image-rs/blob/main/docs/ccv1_image_security_design.md#policy) 
file.

The format of policy file is detailed [here](../docs/ccv1_image_security_design.md#policy).

Each signing scheme works due to the `scheme` field in a [Policy Requirement](https://github.com/containers/image/blob/main/docs/containers-policy.json.5.md#policy-requirements). But also, we have **optimized and expanded** it to support
different signing schemes. A new field `scheme` is added to clearify the signing scheme.

The format of a Policy Requirement may be little different from the mentioned link.

A Policy Requirement claiming a specific signature scheme in the `scheme` field.
Here are some examples for [Simple Signing](src/mechanism/simple/README.md)

```json
{
    "type": "signedBy",
    "scheme": "simple",
    "keyType": "GPGKeys",
    "keyPath": "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release",
}
```

Here, the `signedBy` type shows that this Policy Requirement
requires signature verification. And the `scheme` field will indicate
the concrete signing scheme for this Policy Requirement. The rest of the 
fields may be different due to different signing scheme. 

For example,
[Simple Signing](src/mechanism/simple/README.md) here requires fields
`keyType`, `keyPath`, `keyData`, and `signedIdentity`.

## How to add new Signing Scheme?

For example, a new scheme called `new-sign-scheme` is to be added.
Here are the positions must be modified.

1. `src/mechanism/new-sign-scheme` directory
Create `src/mechanism/new-sign-scheme/mod.rs`

Add `pub mod new_sign_scheme` into  `src/mechanism/mod.rs`

In `src/mechanism/new-sign-scheme/mod.rs`, define the unique parameters 
used in the `policy.json` by `new-sign-scheme`.
For example, a field named `signature-path` should be included, like

```json
// ... A Policy Requirement
{
    "type": "signedBy",
    "scheme": "new-sign-scheme",
    "signature-path": "/keys/123.key",
}
```

Then the parameters' struct can be defined in `src/mechanism/new-sign-scheme/mod.rs`,
like this

```rust
#[derive(Deserialize, Debug, PartialEq, Serialize)]
pub struct NewSignSchemeParameters {
    #[serde(rename = "signature-path")]
    pub signature_path: String,
}
```
And then the field can be deserialized from `policy.json`.

Besides, Implement the trait `SignScheme` for `NewSignSchemeParameters`.
```rust
pub trait SignScheme {
   /// Prepare runtime directories for storing signatures, configuretions ,.etc
    fn prepare_runtime_dirs(&self) -> Result<()>;

    /// Check whether the some resources need to be obtained from KBS.
    /// Any needed resources names are in the `Vec`, and these names are
    /// ResourceDescription in GetResourceRequest of gRPC between AA and kbs.
    /// Please refer to https://github.com/confidential-containers/image-rs/blob/main/docs/ccv1_image_security_design.md#get-resource-service
    fn resources_check(&self) -> Result<Vec<&str>>;

    /// Process all the gathered resources from kbs. All the resources
    /// gathered from kbs due to the return value of `needed_resources_list_from_kbs()`
    /// will be recorded into a HashMap, mapping `resource name` ->
    /// `content of Vec<u8>`. The parameter of this function is the
    /// HashMap.
    fn process_gathered_resources(&self, resources: HashMap<&str, Vec<u8>>) -> Result<()>;

    /// Judge whether an image is allowed by this SignScheme.
    fn allows_image(&self, image: &mut Image) -> Result<()>;
}
```

For a specific signing scheme in a Policy Requirement,
these 5 functions are called in the following order.

```plaintext
+------------+                                          +-----------+
|            |         1.prepare_runtime_dirs()         |           |
|            +----------------------------------------->|           |
|            |                                          |           |
|            |         2.resources_check()              |           |
|            +----------------------------------------->|           |
|            |                                          | signature |
|  image-rs  |                                          |  schemes  |
|            +                                          |           |
|            |                                          |           |
|            |         3.process_gathered_resources()   |           |
|            +----------------------------------------->|           |
|            |                                          |           |
|            |         4.allows_image()                 |           |
|            +----------------------------------------->|           |
|            |                                          |           |
|            |                                          |           |
|            |                                          |           |
+------------+                                          +-----------+
```

* Firstly, `prepare_runtime_dirs()` will prepare the directories that this
signing scheme uses, such as the configurations and signature
files storage dirs.
* Secondly, `resources_check()` function will check all the resources
need to be gathered by Attestation Agent (AA) from kbs, and return 
a `Vec<&str>` containing all these resources' ResourceDescriptions. 
A ResourceDescription is a parameter for gRPC GetResourceRequest 
between AA and kbs. Refer to (get-resource-service)[https://github.com/confidential-containers/image-rs/blob/main/docs/ccv1_image_security_design.md#get-resource-service]
for more information.
* After all the resources is gathered by AA, they will be organized
into a HashMap, with key the resource's Resource Description,
value the content of the resource. This HashMap will be the 
input parameter of `process_gathered_resources()`, and this function
can save the contents into files, or do other things.
* Finally, `allows_image()` will be called to verify the signature,
and check whether this image is allowed.

2. `src/mechanism/mod.rs`.

Add a new enum value `NewSignScheme` for `SignScheme` in 

```rust
pub enum SignSchemeEnum {
    #[serde(rename = "simple")]
    SimpleSigning(SimpleParameters),
    // Here new scheme
    #[serde(rename = "new-sign-scheme")]
    NewSignScheme(NewSignSchemeParameters),
}
```

Fill in the new arm in the following function. 
```rust
pub fn inner_ref(&self) -> Result<()> {
        match self {
            SignSchemeEnum::SimpleSigning(scheme) => scheme,
            // New arm
            SignSchemeEnum::NewSignScheme(scheme) => scheme,
        }
    }
```

## Supported Signatures

|Sign Scheme|Readme|
|---|---|
|[Simple Signing](src/mechanism/simple)| [README](src/mechanism/simple/README.md) |