use std::process::Command;
use std::str;

fn main() {
    let output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .unwrap();

    let git_hash = str::from_utf8(&output.stdout).unwrap().trim();

    println!("cargo:rustc-env=GIT_HASH={}", git_hash);
    println!("cargo:rerun-if-changed=.git/HEAD");
}
