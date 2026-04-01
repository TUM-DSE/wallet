// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 IBM
//
// Author: Claudio Carvalho <cclaudio@linux.ibm.com>

use std::process::Command;
use std::process::Stdio;

fn main() {

    let out_dir = std::env::var("OUT_DIR").unwrap();
    println!("Writting to {out_dir}");
    // Build crypto.
    let status = Command::new("./build.sh")
        .current_dir("src/crypto")
        .env("NIX_ENFORCE_NO_NATIVE", "0")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .unwrap();
    assert!(status.success());
   let status= Command::new("ls")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .unwrap();
    assert!(status.success());

    let status= Command::new("cp")
        .args(["src/crypto/libhaclcrypto.a", &out_dir])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .unwrap();
    assert!(status.success());
    //assert!(false);
    // Tell cargo to link libtcgtpm and where to find it.
    //println!("cargo:rustc-link-search=src/my_crypto/");
    //println!("cargo:rustc-link-lib=my_crypto");
    println!("cargo:rustc-link-search={}",out_dir);
    println!("cargo:rustc-link-lib=haclcrypto");
}
