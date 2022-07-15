// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, Result};
use oci_distribution::Reference;
use serde::{Deserialize, Serialize};
use signature::{Image, Policy};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs;
use std::path::Path;

use get_resource::get_resource_service_client::GetResourceServiceClient;
use get_resource::GetResourceRequest;

const AA_GETRESOURCE_ADDR: &str = "http://127.0.0.1:50001";

// Image security config dir contains important information such as
// security policy configuration file and signature verification configuration file.
// Therefore, it is necessary to ensure that the directory is stored in a safe place.
//
// The reason for using the `/run` directory here is that in general HW-TEE,
// the `/run` directory is mounted in `tmpfs`, which is located in the encrypted memory protected by HW-TEE.
const IMAGE_SECURITY_CONFIG_DIR: &str = "/run/image-security";
const POLICY_FILE_PATH: &str = "/run/image-security/security_policy.json";

mod get_resource {
    #![allow(unknown_lints)]
    #![allow(clippy::derive_partial_eq_without_eq)]
    tonic::include_proto!("getresource");
}

/// The resource description that will be passed to AA when get resource.
#[derive(Serialize, Deserialize, Debug)]
struct ResourceDescription {
    name: String,
    optional: HashMap<String, String>,
}

impl ResourceDescription {
    /// Create a new ResourceDescription with resource name.
    pub fn new(name: &str) -> Self {
        ResourceDescription {
            name: name.to_string(),
            optional: HashMap::new(),
        }
    }
}

/// `security_validate` judges whether the container image is allowed to be pulled and run.
///
/// According to the configuration of the policy file. The policy may include
/// signatures, if a signature of the container image needs to be verified, the
/// specified signature scheme is used for signature verification.
pub async fn security_validate(
    image_reference: &str,
    image_digest: &str,
    aa_kbc_params: &str,
) -> Result<()> {
    if !Path::new(IMAGE_SECURITY_CONFIG_DIR).exists() {
        fs::create_dir_all(IMAGE_SECURITY_CONFIG_DIR)
            .map_err(|e| anyhow!("Create image security runtime config dir failed: {:?}", e))?;
    }

    // if Policy config file does not exist, get if from KBS.
    if !Path::new(POLICY_FILE_PATH).exists() {
        let policy_json = String::from_utf8(get_resource_from_kbs("Policy", aa_kbc_params).await?)?;
        fs::write(POLICY_FILE_PATH, policy_json)?;
    }

    let policy = Policy::from_file(POLICY_FILE_PATH)?;

    let reference = Reference::try_from(image_reference)?;
    let mut image = Image::default_with_reference(reference);
    image.set_manifest_digest(image_digest)?;

    // Read the set of signature schemes that need to be verified
    // of the image from the policy configuration.
    let schemes = policy.signature_schemes(&image);

    // For each signature scheme, create the runtime directory,
    // and get the necessary resources from KBS if needed.
    for scheme in schemes {
        let scheme = scheme.inner_ref();
        scheme.prepare_runtime_dirs()?;

        let resource_names = scheme.resources_check()?;
        let resources = get_scheme_resources(resource_names, aa_kbc_params).await?;
        scheme.process_gathered_resources(resources)?;
    }

    policy
        .is_image_allowed(image)
        .map_err(|e| anyhow!("Validate image failed: {:?}", e))
}

/// Get scheme resources from KBS and record them in a HashMap.
async fn get_scheme_resources<'a, 'b>(
    resources: Vec<&'b str>,
    aa_kbc_params: &'a str,
) -> Result<HashMap<&'b str, Vec<u8>>> {
    let mut res = HashMap::new();
    for resource in resources {
        let data = get_resource_from_kbs(resource, aa_kbc_params).await?;
        res.insert(resource, data);
    }

    Ok(res)
}

async fn get_resource_from_kbs(resource_name: &str, aa_kbc_params: &str) -> Result<Vec<u8>> {
    if let Some((kbc_name, kbs_uri)) = aa_kbc_params.split_once("::") {
        if kbc_name.is_empty() {
            return Err(anyhow!("aa_kbc_params: missing KBC name"));
        }

        if kbs_uri.is_empty() {
            return Err(anyhow!("aa_kbc_params: missing KBS URI"));
        }

        let mut client = GetResourceServiceClient::connect(AA_GETRESOURCE_ADDR).await?;
        let resource_desc = serde_json::to_string(&ResourceDescription::new(resource_name))?;
        let req = tonic::Request::new(GetResourceRequest {
            kbc_name: kbc_name.into(),
            kbs_uri: kbs_uri.into(),
            resource_description: resource_desc,
        });
        let res = client.get_resource(req).await?;

        Ok(res.into_inner().resource)
    } else {
        Err(anyhow!("aa_kbc_params: KBC/KBS pair not found"))
    }
}
