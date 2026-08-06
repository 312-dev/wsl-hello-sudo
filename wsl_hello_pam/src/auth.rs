use crate::bindings::*;
use libc::{c_char, c_int};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use sha2::Sha256;
use std::borrow::Cow;
use std::ffi::{CStr, CString};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, prelude::*, SeekFrom};
use std::path::Path;
use std::process::{Command, Stdio};
use std::ptr;

#[no_mangle]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut pam_handle_t,
    flags: c_int,
    _: c_int,
    _: *mut *const c_char,
) -> c_int {
    authenticate_via_hello(pamh).unwrap_or_else(|err| {
        if (flags & PAM_SILENT) == 0 {
            println!("WSL Hello error: {}", err);
        }
        match err {
            HelloAuthenticationError::PublicKeyFileError(ref err)
                if err.kind() == io::ErrorKind::NotFound =>
            {
                PAM_USER_UNKNOWN
            }
            HelloAuthenticationError::AuthenticatorLaunchError(_) => PAM_AUTHINFO_UNAVAIL,
            HelloAuthenticationError::AuthenticatorConnectionError(_) => PAM_AUTHINFO_UNAVAIL,
            HelloAuthenticationError::AuthenticatorSignalled => PAM_AUTHINFO_UNAVAIL,
            _ => PAM_AUTH_ERR,
        }
    })
}

fn get_user(pamh: *mut pam_handle_t, prompt: Option<&str>) -> Result<Cow<'_, str>, i32> {
    let mut c_user: *const c_char = ptr::null();
    let tmp_prompt_str: CString;
    let c_prompt = match prompt {
        Some(prompt_str) => {
            tmp_prompt_str = CString::new(prompt_str).unwrap();
            tmp_prompt_str.as_ptr()
        }
        None => ptr::null(),
    };
    let err;
    unsafe {
        err = pam_get_user(pamh, &mut c_user, c_prompt);
    }
    match err {
        PAM_SUCCESS => unsafe {
            let c_user_str = CStr::from_ptr(c_user);
            Ok(c_user_str.to_string_lossy())
        },
        err => Err(err),
    }
}

#[derive(Debug)]
enum ConfigError {
    Io(io::Error),
    MissingField(String),
    InvalidValueType(String),
}

impl From<io::Error> for ConfigError {
    fn from(err: io::Error) -> ConfigError {
        ConfigError::Io(err)
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ConfigError::Io(ref ioerr) => write!(f, "{}", ioerr),
            ConfigError::MissingField(ref field) => write!(f, "field: '{}' is not found", field),
            ConfigError::InvalidValueType(ref field) => {
                write!(f, "field: '{}' has an invalid value type", field)
            }
        }
    }
}

/// Reads one `key = "value"` entry from /etc/pam_wsl_hello/config.
///
/// The installer only ever writes two double-quoted scalars, so this replaces a
/// full TOML parser plus serde in the auth path with a dozen obvious lines.
/// Blank lines and `#` comments are skipped; values must be double-quoted.
fn get_config_value(key: &str) -> Result<String, ConfigError> {
    let mut config_file = File::open("/etc/pam_wsl_hello/config")?;
    let mut config = String::new();
    config_file.read_to_string(&mut config)?;

    for line in config.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = match line.split_once('=') {
            Some(pair) => pair,
            None => continue,
        };
        if name.trim() != key {
            continue;
        }
        let value = value.trim();
        return value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .map(|v| v.to_owned())
            .ok_or_else(|| ConfigError::InvalidValueType(key.to_owned()));
    }

    Err(ConfigError::MissingField(key.to_owned()))
}

fn get_authenticator_path() -> Result<String, ConfigError> {
    get_config_value("authenticator_path")
}

fn get_win_mnt() -> Result<String, ConfigError> {
    get_config_value("win_mnt")
}

#[derive(Debug)]
enum HelloAuthenticationError {
    GetUserError(i32),
    ConfigError(ConfigError),
    PublicKeyFileError(io::Error),
    Io(io::Error),
    InvalidPublicKey(rsa::pkcs8::spki::Error),
    MalformedSignature,
    NonceError,
    AuthenticatorLaunchError(io::Error),
    AuthenticatorConnectionError(io::Error),
    AuthenticatorSignalled,
    HelloAuthenticationFail(String),
    SignAuthenticationFail,
}

impl From<io::Error> for HelloAuthenticationError {
    fn from(err: io::Error) -> HelloAuthenticationError {
        HelloAuthenticationError::Io(err)
    }
}

impl From<ConfigError> for HelloAuthenticationError {
    fn from(err: ConfigError) -> HelloAuthenticationError {
        HelloAuthenticationError::ConfigError(err)
    }
}

impl fmt::Display for HelloAuthenticationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HelloAuthenticationError::ConfigError(ref err) => write!(f, "config error; {}", err),
            HelloAuthenticationError::PublicKeyFileError(ref err) => match err.kind() {
                io::ErrorKind::NotFound => {
                    write!(f, "cannot find the credential public key for this user")
                }
                _ => write!(f, "{}", err),
            },
            HelloAuthenticationError::Io(ref err) => write!(f, "{}", err),
            HelloAuthenticationError::GetUserError(code) => {
                write!(
                    f,
                    "cannot determine the PAM user; pam_get_user returned {code}"
                )
            }
            HelloAuthenticationError::InvalidPublicKey(ref err) => {
                write!(f, "the pem file of the public key is invalid; {err}")
            }
            HelloAuthenticationError::MalformedSignature => {
                write!(f, "Windows Hello returned a malformed signature")
            }
            HelloAuthenticationError::NonceError => {
                write!(f, "cannot obtain randomness from the OS for the challenge")
            }
            HelloAuthenticationError::AuthenticatorLaunchError(ref err) => {
                write!(f, "cannot launch Windows Hello; {}", err)
            }
            HelloAuthenticationError::AuthenticatorConnectionError(ref err) => {
                write!(f, "cannot communicate with Windows Hello; {}", err)
            }
            HelloAuthenticationError::HelloAuthenticationFail(ref msg) => {
                write!(f, "authentication failed; {}", msg)
            }
            HelloAuthenticationError::SignAuthenticationFail => write!(
                f,
                "the result of signature verification of the credential is failure"
            ),
            ref err => write!(f, "internal error; {:?}", err),
        }
    }
}

fn authenticate_via_hello(pamh: *mut pam_handle_t) -> Result<i32, HelloAuthenticationError> {
    let user_name = get_user(pamh, None).map_err(HelloAuthenticationError::GetUserError)?;
    let credential_key_name = format!("pam_wsl_hello_{}", user_name);

    let mut hello_public_key_file = File::open(format!(
        "/etc/pam_wsl_hello/public_keys/{}.pem",
        credential_key_name
    ))
    .map_err(HelloAuthenticationError::PublicKeyFileError)?;
    let mut key_str = String::new();
    hello_public_key_file.read_to_string(&mut key_str)?;
    let hello_public_key = RsaPublicKey::from_public_key_pem(&normalize_public_key_pem(&key_str))
        .map_err(HelloAuthenticationError::InvalidPublicKey)?;

    // 256 bits straight from the OS CSPRNG. This nonce is the only thing standing
    // between this scheme and a replay of a previously observed signature, so it
    // comes from getrandom rather than a userspace PRNG.
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| HelloAuthenticationError::NonceError)?;
    let nonce_hex = nonce.iter().fold(String::with_capacity(64), |mut acc, b| {
        acc.push_str(&format!("{:02x}", b));
        acc
    });
    let challenge = format!("pam_wsl_hello:{}:{}", user_name, nonce_hex);

    let auth_res;
    let challenge_tmpfile_path = &format!("/tmp/{}", challenge);
    {
        // Since there seems to be a bug that C# applications cannot read from pipes on WSL,
        // we create a temporary file to redirect
        let mut challenge_tmpfile = OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .open(challenge_tmpfile_path)?;
        challenge_tmpfile.write_all(challenge.as_bytes())?;
        challenge_tmpfile.seek(SeekFrom::Start(0))?;

        let challenge_tmpfile_in = Stdio::from(challenge_tmpfile);

        let authenticator_path = get_authenticator_path()?;
        let authenticator = Command::new(&authenticator_path)
            .arg("authenticator")
            .arg(credential_key_name)
            .current_dir(Path::new(&get_win_mnt()?))
            .stdin(challenge_tmpfile_in)
            .stdout(Stdio::piped())
            .spawn()
            .map_err(HelloAuthenticationError::AuthenticatorLaunchError)?;

        auth_res = authenticator
            .wait_with_output()
            .map_err(HelloAuthenticationError::AuthenticatorConnectionError)?;
    }
    fs::remove_file(challenge_tmpfile_path)?;

    match auth_res.status.code() {
        Some(0) => { /* Success */ }
        Some(_) => {
            return Err(HelloAuthenticationError::HelloAuthenticationFail(
                String::from_utf8(auth_res.stdout)
                    .unwrap_or_else(|_| "invalid utf8 output".to_string()),
            ))
        }
        None => return Err(HelloAuthenticationError::AuthenticatorSignalled),
    }
    let signature = auth_res.stdout;

    verify_signature(hello_public_key, challenge.as_bytes(), &signature)?;
    Ok(PAM_SUCCESS)
}

/// Re-wraps a PUBLIC KEY PEM body to 64 columns.
///
/// WindowsHelloBridge writes the base64 as a single unwrapped line, which
/// OpenSSL accepted but RFC 7468 does not allow and RustCrypto's strict
/// pem-rfc7468 parser rejects. Normalising here keeps every key that was ever
/// created by an older build working, instead of requiring a re-enrolment.
fn normalize_public_key_pem(pem: &str) -> String {
    const HEADER: &str = "-----BEGIN PUBLIC KEY-----";
    const FOOTER: &str = "-----END PUBLIC KEY-----";

    let body: String = pem
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("-----"))
        .collect();

    let mut out = String::with_capacity(body.len() + HEADER.len() + FOOTER.len() + 64);
    out.push_str(HEADER);
    out.push('\n');
    // base64 is ASCII, so chunking the bytes at 64 never splits a character.
    for chunk in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(FOOTER);
    out.push('\n');
    out
}

/// Verifies an RSA PKCS#1 v1.5 / SHA-256 signature over `challenge`.
///
/// This single check is what stands between a Windows Hello gesture and a root
/// shell, so it is factored out of the PAM flow to be directly unit testable.
/// It fails closed: every error path is a rejection, never a grant.
fn verify_signature(
    public_key: RsaPublicKey,
    challenge: &[u8],
    signature: &[u8],
) -> Result<(), HelloAuthenticationError> {
    let verifying_key = VerifyingKey::<Sha256>::new(public_key);
    let signature =
        Signature::try_from(signature).map_err(|_| HelloAuthenticationError::MalformedSignature)?;

    verifying_key
        .verify(challenge, &signature)
        .map_err(|_| HelloAuthenticationError::SignAuthenticationFail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::RsaPrivateKey;

    fn keypair() -> (SigningKey<Sha256>, RsaPublicKey) {
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, 2048).expect("keygen");
        let public = private.to_public_key();
        (SigningKey::<Sha256>::new(private), public)
    }

    #[test]
    fn accepts_a_genuine_signature() {
        let (signing_key, public) = keypair();
        let challenge = b"pam_wsl_hello:gray:deadbeef";
        let sig = signing_key.sign(challenge).to_vec();

        assert!(verify_signature(public, challenge, &sig).is_ok());
    }

    #[test]
    fn rejects_a_signature_over_a_different_challenge() {
        let (signing_key, public) = keypair();
        let sig = signing_key.sign(b"pam_wsl_hello:gray:aaaaaaaa").to_vec();

        // A replayed signature must not authenticate a fresh nonce.
        assert!(verify_signature(public, b"pam_wsl_hello:gray:bbbbbbbb", &sig).is_err());
    }

    #[test]
    fn rejects_a_signature_from_the_wrong_key() {
        let (signing_key, _) = keypair();
        let (_, other_public) = keypair();
        let challenge = b"pam_wsl_hello:gray:deadbeef";
        let sig = signing_key.sign(challenge).to_vec();

        assert!(verify_signature(other_public, challenge, &sig).is_err());
    }

    #[test]
    fn rejects_garbage_and_empty_signatures() {
        let (_, public) = keypair();
        let challenge = b"pam_wsl_hello:gray:deadbeef";

        assert!(verify_signature(public.clone(), challenge, &[]).is_err());
        assert!(verify_signature(public.clone(), challenge, &[0u8; 256]).is_err());
        assert!(verify_signature(public, challenge, b"not a signature").is_err());
    }

    /// Collapses a wrapped PEM into the single-line shape WindowsHelloBridge writes.
    fn unwrap_pem(pem: &str) -> String {
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            body
        )
    }

    #[test]
    fn accepts_the_unwrapped_pem_windows_actually_emits() {
        let (signing_key, public) = keypair();
        let unwrapped = unwrap_pem(&public.to_public_key_pem(Default::default()).expect("pem"));

        // Precondition: without normalising, the strict RFC 7468 parser refuses it.
        // If this ever starts passing, the rest of this test is vacuous.
        assert!(
            RsaPublicKey::from_public_key_pem(&unwrapped).is_err(),
            "strict parser unexpectedly accepted an unwrapped PEM"
        );

        let key = RsaPublicKey::from_public_key_pem(&normalize_public_key_pem(&unwrapped))
            .expect("normalised PEM must parse");
        let challenge = b"pam_wsl_hello:gray:deadbeef";
        let sig = signing_key.sign(challenge).to_vec();
        assert!(verify_signature(key, challenge, &sig).is_ok());
    }

    #[test]
    fn normalizing_an_already_wrapped_pem_is_a_no_op() {
        let (_, public) = keypair();
        let wrapped = public.to_public_key_pem(Default::default()).expect("pem");
        assert_eq!(normalize_public_key_pem(&wrapped), wrapped);
    }

    #[test]
    fn public_key_survives_a_pem_round_trip() {
        let (signing_key, public) = keypair();
        let pem = public.to_public_key_pem(Default::default()).expect("pem");
        let reparsed = RsaPublicKey::from_public_key_pem(&pem).expect("parse");

        let challenge = b"pam_wsl_hello:gray:deadbeef";
        let sig = signing_key.sign(challenge).to_vec();
        assert!(verify_signature(reparsed, challenge, &sig).is_ok());
    }
}
