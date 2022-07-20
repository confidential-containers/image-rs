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
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::Image;

use self::simple::SimpleParameters;

pub mod simple;

// TODO: Add more signature mechanism.
//
// Refer to issue: https://github.com/confidential-containers/image-rs/issues/7

/// Signing schemes enum.
/// * `SimpleSigning`: Redhat simple signing.
#[derive(Deserialize, Debug, PartialEq, Serialize, EnumIter)]
#[serde(tag = "scheme")]
pub enum SignSchemeEnum {
    #[serde(rename = "simple")]
    SimpleSigning(SimpleParameters),
}

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

impl SignSchemeEnum {
    /// Returns the reference of the inner SignScheme trait object,
    /// to help call functions in SignScheme
    pub fn inner_ref(&self) -> &dyn SignScheme {
        match self {
            SignSchemeEnum::SimpleSigning(scheme) => scheme,
        }
    }
}

/// Initialize all the Signschemes
pub async fn init_all_signing_schemes() -> Result<()> {
    for scheme in SignSchemeEnum::iter() {
        scheme.inner_ref().init().await?;
    }

    Ok(())
}
