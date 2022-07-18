// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! # Signing schemes
//! different signatures defination and the top level interfaces.
//!
//! ### Design
//! We use both an enum and a struct for a signing scheme.
//! * `SignSchemeEnum`: The member inside the enum value is a
//! struct, which implements the trait `SignScheme`.
//! * `SignScheme`: A trait containing basic interface for the
//! sign scheme.
//!
//! Why we use an extra enum here is to help divide traits into
//! object safe and object unsafe traits (like `Deserialize`, `Serialize`).
//! The enum has all the object unsafe traits, and the trait has
//! object safe traits. Thus enum can be deserialized from `policy.json`.
//! Also, by call `inner_ref()` can get the reference of the inner
//! trait object to do all the trait functions.

use std::collections::HashMap;

use anyhow::*;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::Image;

use self::simple::SimpleParameters;

pub mod simple;

// TODO: Add more signature mechanism.
//
// Refer to issue: https://github.com/confidential-containers/image-rs/issues/7

/// Signing schemes enum.
/// * `SimpleSigning`: Redhat simple signing.
#[derive(Deserialize, Debug, PartialEq, Serialize)]
#[serde(tag = "scheme")]
pub enum SignSchemeEnum {
    #[serde(rename = "simple")]
    SimpleSigning(SimpleParameters),
}

/// The interface of a signing scheme
#[async_trait]
pub trait SignScheme {
    /// Prepare runtime directories for storing signatures, configuretions ,.etc
    async fn prepare_runtime_dirs(&self) -> Result<()>;

    /// Check whether the some resources need to be obtained from KBS.
    /// Any needed resources names are in the `Vec`. Each name is the `name` field of
    /// a ResourceDescription. ResourceDescription is for GetResourceRequest, which
    /// is the gRPC between AA and kbs.
    /// Please refer to https://github.com/confidential-containers/image-rs/blob/main/docs/ccv1_image_security_design.md#get-resource-service
    /// for more information about `name` file of ResourceDescription.
    async fn resources_check(&self) -> Result<Vec<&str>>;

    /// Process all the gathered resources from kbs. All the resources
    /// gathered from kbs due to the return value of `needed_resources_list_from_kbs()`
    /// will be recorded into a HashMap, mapping `resource name` ->
    /// `content of Vec<u8>`. The parameter of this function is the
    /// HashMap.
    async fn process_gathered_resources(&self, resources: HashMap<&str, Vec<u8>>) -> Result<()>;

    /// Judge whether an image is allowed by this SignScheme.
    async fn allows_image(&self, image: &mut Image) -> Result<()>;
}

impl SignSchemeEnum {
    /// Returns the reference of the inner SignScheme trait object,
    /// to help call functions in SignScheme
    pub fn inner_ref(&self) -> &dyn SignScheme {
        match self {
            SignSchemeEnum::SimpleSigning(scheme) => scheme,
        }
    }
}
