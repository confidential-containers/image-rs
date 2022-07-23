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

### `src/mechanism/new-sign-scheme` directory
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
/// The interface of a signing scheme
#[async_trait]
pub trait SignScheme {
    /// Do initialization jobs for this scheme. This may include the following
    /// * preparing runtime directories for storing signatures, configurations, etc.
    /// * gathering necessary files.
    async fn init(&self) -> Result<()>;

    /// Reture a HashMap including a resource's name => file path in fs.
    /// 
    /// Here `resource's name` is the `name` field for a ResourceDescription
    /// in GetResourceRequest.
    /// Please refer to https://github.com/confidential-containers/image-rs/blob/main/docs/ccv1_image_security_design.md#get-resource-service
    /// for more information about the `GetResourceRequest`.
    /// 
    /// This function will be called by `Agent`, to get the manifest
    /// of all the resources to be gathered from kbs. The gathering
    /// operation will happen after `init_scheme()`, to prepare necessary
    /// resources. The HashMap here uses &str rather than String,
    /// which encourages developer of new signing schemes to define
    /// const &str for these information.
    fn resource_manifest(&self) -> HashMap<&str, &str>;

    /// Judge whether an image is allowed by this SignScheme.
    async fn allows_image(&self, image: &mut Image) -> Result<()>;
}
```

The basic architecture for signature verification is the following figure:

```plaintext
                +-------------+
                | ImageClient |
                +-------------+
                       |
                       |
                       v
              +-----------------+   gRPC Client
              | Signature-Agent | ---------------> KBS
              +-----------------+    Access
                       |
                       |
      +----------------+-----------------+
      |                                  |
      |                                  |
+-----+-------+                   +------+------+
|   Signing   |                   |   Signing   |
|    Scheme   |                   |    Scheme   |
|   Module 1  |                   |   Module 2  |
+-------------+                   +-------------+
```

When a `ImageClient` need to pull an image, it will instanialize
a `Signature-Agent` to handle Policy Requirements if needed.
The `Signature-Agent` can communicate with KBS to retrieve needed
resources. Also, it can call specific signing scheme verification
module to verify a signature due to the Policy Requirement in
`policy.json`. So there must be three interfaces for a signing
scheme to implement:
1. `init()`: This function is called **once** every
initialization of a new `Signature-Agent` instance.
It can do initialization work for this scheme. This may include the following
* preparing runtime directories for storing signatures, configurations, etc.
* gathering necessary files.

2. `resource_manifest()`: This function will tell the `Signature-Agent`
which resources it need to retrieve from the kbs. The return value should be
a HashMap. The key of the HashMap is the `name` field for a ResourceDescription
in GetResourceRequest. The value is the file path that the returned resource will be
written into after retrieving the resource. Refer to 
[get-resource-service](https://github.com/confidential-containers/image-rs/blob/main/docs/ccv1_image_security_design.md#get-resource-service)
for more information about GetResourceRequest. This function will be called
on every check for a Policy Requirement of this signing scheme.

3. `allows_image()`: This function will do the verification. This
function will be called on every check for a Policy Requirement of this signing scheme.

### `src/mechanism/mod.rs`

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