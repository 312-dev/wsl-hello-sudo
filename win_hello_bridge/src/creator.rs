use crate::FailureReason;
use windows::Security::{
    Credentials::{KeyCredentialCreationOption, KeyCredentialManager},
    Cryptography::CryptographicBuffer,
};

pub(crate) fn create_public_key(key_name: &str) -> Result<String, FailureReason> {
    // Windows 11 25H2 (build 26200) raises a raw NCrypt error 0x80098044 from
    // RequestCreateAsync(FailIfExists) instead of returning the documented
    // CredentialAlreadyExists status, so the original catch branch is unreachable.
    // Probe with OpenAsync and only create when the credential is genuinely absent;
    // ReplaceExisting is safe there because we know there is nothing to clobber.
    let public_key = {
        let existing = KeyCredentialManager::OpenAsync(key_name)?.get()?;

        match FailureReason::from_credential_status(existing.Status()?, key_name) {
            Ok(()) => existing
                .Credential()?
                .RetrievePublicKeyWithDefaultBlobType()?,
            Err(FailureReason::CredentialNotFound(_)) => {
                let result = KeyCredentialManager::RequestCreateAsync(
                    key_name,
                    KeyCredentialCreationOption::ReplaceExisting,
                )?
                .get()?;
                FailureReason::from_credential_status(result.Status()?, key_name)?;
                result
                    .Credential()?
                    .RetrievePublicKeyWithDefaultBlobType()?
            }
            Err(e) => return Err(e),
        }
    };

    // RFC 7468 requires the base64 body wrapped at 64 columns. Earlier builds
    // emitted one long line, which OpenSSL tolerated but strict parsers reject.
    let base64 = CryptographicBuffer::EncodeToBase64String(public_key)?.to_string();
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in base64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");

    Ok(pem)
}
