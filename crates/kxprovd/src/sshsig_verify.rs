//! OpenSSH SSHSIG verification (`ssh-keygen -Y verify` semantics, v2.6 F1).

use kxprov_api::MODE_SSH_NAMESPACE;
use ssh_key::{PublicKey, SshSig};
use std::path::Path;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SshsigError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("ssh key: {0}")]
    Key(#[from] ssh_key::Error),
    #[error("signer not pinned")]
    NotPinned,
}

fn parse_allowed_signers_line(line: &str) -> Option<(String, PublicKey)> {
    let line = line.split('#').next()?.trim();
    if line.is_empty() {
        return None;
    }
    let mut parts = line.split_whitespace();
    let namespaces = parts.next()?;
    let key_type = parts.next()?;
    let key_b64 = parts.next()?;
    let openssh = format!("{key_type} {key_b64}");
    let pk = PublicKey::from_openssh(&openssh).ok()?;
    Some((namespaces.to_string(), pk))
}

fn namespace_matches(line_ns: &str, expect: &str) -> bool {
    line_ns.split(',').any(|n| n.trim() == expect)
}

/// Verify a PEM SSHSIG over `message` against pinned allowed signers.
pub fn verify_ssh_signature(
    message: &[u8],
    signature_pem: &str,
    allowed_signers: &Path,
    expect_namespace: &str,
) -> Result<(), SshsigError> {
    let sshsig = SshSig::from_str(signature_pem.trim())?;
    let data = std::fs::read_to_string(allowed_signers)?;
    for line in data.lines() {
        let Some((ns, allowed)) = parse_allowed_signers_line(line) else {
            continue;
        };
        if !namespace_matches(&ns, expect_namespace) {
            continue;
        }
        if allowed.key_data() != sshsig.public_key() {
            continue;
        }
        allowed.verify(expect_namespace, message, &sshsig)?;
        return Ok(());
    }
    Err(SshsigError::NotPinned)
}

pub fn verify_mode_nonce(
    nonce: &[u8],
    signature_pem: &str,
    allowed_signers: &Path,
) -> Result<(), SshsigError> {
    verify_ssh_signature(nonce, signature_pem, allowed_signers, MODE_SSH_NAMESPACE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn roundtrip_ssh_keygen_sign_rust_verify() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("key");
        let nonce = dir.path().join("nonce.txt");
        let sig = dir.path().join("nonce.txt.sig");
        let allowed = dir.path().join("allowed");
        Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-f"])
            .arg(&key)
            .args(["-N", ""])
            .status()
            .unwrap();
        std::fs::write(&nonce, b"nonce-bytes\n").unwrap();
        Command::new("ssh-keygen")
            .args([
                "-Y",
                "sign",
                "-f",
                key.to_str().unwrap(),
                "-n",
                MODE_SSH_NAMESPACE,
            ])
            .arg(&nonce)
            .status()
            .unwrap();
        let pub_line = String::from_utf8(
            Command::new("ssh-keygen")
                .args(["-y", "-f"])
                .arg(&key)
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        let parts: Vec<_> = pub_line.split_whitespace().collect();
        std::fs::write(
            &allowed,
            format!("{} {} {}\n", MODE_SSH_NAMESPACE, parts[0], parts[1]),
        )
        .unwrap();
        let pem = std::fs::read_to_string(sig).unwrap();
        verify_mode_nonce(b"nonce-bytes\n", &pem, &allowed).unwrap();
    }
}
