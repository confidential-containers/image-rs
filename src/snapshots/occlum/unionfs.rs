// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

// This unionfs file is used for occlum only

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;

use anyhow::{anyhow, Result};
use dircpy::CopyBuilder;
use fs_extra;
use fs_extra::dir;
use nix::mount::MsFlags;

use crate::snapshots::{MountPoint, Snapshotter};

#[derive(Debug)]
pub struct Unionfs {
    pub data_dir: PathBuf,
    pub index: AtomicUsize,
}

fn clear_path(mount_path: &Path) -> Result<()> {
    let mut from_paths = Vec::new();
    let paths = fs::read_dir(
        mount_path
            .to_str()
            .ok_or(anyhow!("mount_path does not exist"))?,
    )?;
    for path in paths {
        from_paths.push(path?.path());
    }
    fs_extra::remove_items(&from_paths)?;

    Ok(())
}

fn create_dir(create_path: &PathBuf) -> Result<()> {
    if !create_path.exists() {
        fs::create_dir_all(create_path.as_path())?;
    }

    Ok(())
}

fn create_environment(mount_path: &Path) -> Result<()> {
    let mut from_paths = Vec::new();
    let mut copy_options = dir::CopyOptions::new();
    copy_options.overwrite = true;

    #[cfg(target_arch = "x86_64")]
    {
        // copy the libs required by occlum to the mount path
        from_paths.push(PathBuf::from("/lib64/ld-linux-x86-64.so.2"));
        let mount_path_lib64 = mount_path;
        let path_lib64 = mount_path_lib64.join("lib64");
        create_dir(&path_lib64)?;

        fs_extra::copy_items(&from_paths, &path_lib64, &copy_options)?;
        from_paths.clear();
    }

    let mount_path_opt = mount_path;
    let path_opt = mount_path_opt
        .join("opt")
        .join("occlum")
        .join("glibc")
        .join("lib");
    fs::create_dir_all(&path_opt)?;

    let occlum_lib = vec![
        "libc.so.6",
        "libdl.so.2",
        "libm.so.6",
        "libpthread.so.0",
        "libresolv.so.2",
        "librt.so.1",
    ];
    let ori_occlum_lib_path = Path::new("/opt/occlum/glibc/lib");
    for lib in occlum_lib.iter() {
        from_paths.push(ori_occlum_lib_path.join(lib));
    }
    fs_extra::copy_items(&from_paths, &path_opt, &copy_options)?;
    from_paths.clear();

    let sys_path = vec!["dev", "etc", "host", "lib", "proc", "root", "sys", "tmp"];
    for path in sys_path.iter() {
        create_dir(&mount_path.join(path))?;
    }

    Ok(())
}

impl Snapshotter for Unionfs {
    fn mount(&mut self, layer_path: &[&str], mount_path: &Path) -> Result<MountPoint> {
        // From the description of https://github.com/occlum/occlum/blob/master/docs/runtime_mount.md#1-mount-trusted-unionfs-consisting-of-sefss ,
        // the source type of runtime mount is "unionfs".
        let fs_type = String::from("unionfs");
        let source = Path::new(&fs_type);

        if !mount_path.exists() {
            fs::create_dir_all(mount_path)?;
        }

        // store the rootfs in different places according to the cid
        let cid = mount_path
            .parent()
            .ok_or(anyhow!("parent do not exist"))?
            .file_name()
            .ok_or(anyhow!("Unknown error: file name pasre fail"))?;
        let sefs_base = Path::new("/images").join(cid).join("sefs");
        let unionfs_lowerdir = sefs_base.join("lower");
        let unionfs_upperdir = sefs_base.join("upper");

        // For mounting trusted UnionFS at runtime of occlum,
        // you can refer to https://github.com/occlum/occlum/blob/master/docs/runtime_mount.md#1-mount-trusted-unionfs-consisting-of-sefss.
        // "c7-32-b3-ed-44-df-ec-7b-25-2d-9a-32-38-8d-58-61" is a hardcode key used to encrypt or decrypt the FS currently,
        // and it will be replaced with dynamic key in the near future.
        let options = format!(
            "lowerdir={},upperdir={},key={}",
            unionfs_lowerdir.display(),
            unionfs_upperdir.display(),
            "c7-32-b3-ed-44-df-ec-7b-25-2d-9a-32-38-8d-58-61"
        );

        let flags = MsFlags::empty();

        nix::mount::mount(
            Some(source),
            mount_path,
            Some(fs_type.as_str()),
            flags,
            Some(options.as_str()),
        )
        .map_err(|e| {
            anyhow!(
                "failed to mount {:?} to {:?}, with error: {}",
                source,
                mount_path,
                e
            )
        })?;

        // clear the mount_path if there is something
        clear_path(mount_path)?;

        // copy dirs to the specified mount directory
        let mut layer_path_vec = layer_path.to_vec();
        let len = layer_path_vec.len();
        for _i in 0..len {
            let layer = layer_path_vec
                .pop()
                .ok_or(anyhow!("Pop() failed from Vec"))?;
            CopyBuilder::new(layer, &mount_path).overwrite(true).run()?;
        }

        // create environment for Occlum
        create_environment(mount_path)?;

        nix::mount::umount(mount_path)?;

        Ok(MountPoint {
            r#type: fs_type,
            mount_path: mount_path.to_path_buf(),
            work_dir: self.data_dir.to_path_buf(),
        })
    }

    fn unmount(&self, mount_point: &MountPoint) -> Result<()> {
        nix::mount::umount(mount_point.mount_path.as_path())?;

        Ok(())
    }
}
