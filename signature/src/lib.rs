// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! # Overall
//! For signature verification in Confidential-Containers.
//!
//! # Usage
//! create a new agent
//!
//! ```no_run
//!
//! // For example kbc
//! let aa_kbc_params = "null_kbc::null";
//!
//! let mut agent = signature::Agent::new(aa_kbc_params).await?;
//!
//! // Check an image
//! agent.allows_image(
//!     image_url,
//!     &image_digest,
//!     )
//!     .await
//!     .map_err(|e| anyhow!("Security validate failed: {:?}", e))?;
//! ```

#[macro_use]
extern crate strum;

pub mod agent;
mod image;
pub mod mechanism;
mod policy;

pub use agent::Agent;
pub use image::Image;
pub use mechanism::init_all_signing_schemes;
pub use mechanism::SignScheme;
pub use mechanism::SignSchemeEnum;
pub use policy::Policy;
