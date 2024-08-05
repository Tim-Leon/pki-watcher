use der::Decode;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls_platform_verifier::Verifier;
use sec1::EcPrivateKey;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;
use x509_parser::x509::SubjectPublicKeyInfo;

use crate::Identity;
use crate::validate::PkiValidatorConfiguration;

#[derive(thiserror::Error, Debug)]
pub enum ValidateCertificateError {
    #[error("Certificate subject:{0} does not match domain name:{1}")]
    NonMatchingServerName(String, String),
    #[error("Certificate expired")]
    CertificateHasExpired,
    #[error("Certificate is self signed")]
    CertificateSelfSigned,
    #[error("InvalidCertificateChain")]
    InvalidCertificateChain,
    #[error("InvalidCertificateSignature")]
    InvalidCertificateSignature,
}

pub fn is_self_signed(cert: &X509Certificate) -> bool {
    if cert.subject() == cert.issuer() {
        if cert.verify_signature(None).is_ok() {
            return true;
        } else if cert.subject() == cert.issuer() {
            panic!("pki looks self-signed, but signature verification failed");
        }
    }
    return false;
}

pub fn validate_certificate_domain(cert: &X509Certificate, server_name: &ServerName) -> bool {
    let subject = cert.subject().to_string();
    let name = ServerName::try_from(subject).unwrap();
    return name == *server_name;
}

pub fn is_certificate_expired(x509: &X509Certificate) -> bool {
    !x509.validity.is_valid()
}

pub fn validate_signature(cert: &X509Certificate, private_key: &PrivateKeyDer) -> bool {
    let (_, subject_public_key) = match private_key {
        PrivateKeyDer::Pkcs1(pkcs1) => {
            SubjectPublicKeyInfo::from_der(pkcs1.secret_pkcs1_der()).unwrap()
        }
        PrivateKeyDer::Sec1(sec1) => {
            let public = EcPrivateKey::from_der(sec1.secret_sec1_der())
                .unwrap()
                .public_key
                .unwrap();
            SubjectPublicKeyInfo::from_der(public).unwrap()
        }
        PrivateKeyDer::Pkcs8(pkcs8) => {
            let public = pkcs8::PrivateKeyInfo::from_der(pkcs8.secret_pkcs8_der())
                .unwrap()
                .public_key
                .unwrap();

            SubjectPublicKeyInfo::from_der(public).unwrap()
        }
        _ => {
            return false;
        }
    };
    cert.verify_signature(Some(&subject_public_key)).is_ok()
}
pub fn validate_certificate_chain(
    verifier: &Verifier,
    end: &X509Certificate,
    intermediates: &Vec<X509Certificate>,
    server_name: &ServerName,
) -> bool {
    let end = CertificateDer::from(end.as_ref());
    let intermediates: Vec<_> = intermediates
        .into_iter()
        .map(|cert| CertificateDer::from(cert.as_ref()))
        .collect();
    let now_time = pki_types::UnixTime::now();
    let ocsp_response = Vec::<u8>::new();

    let verified_certs = verifier
        .verify_server_cert(
            &end,
            &intermediates,
            server_name,
            ocsp_response.as_slice(),
            now_time,
        )
        .unwrap();
    dbg!(verified_certs);
    return true;
}

pub struct PkiValidatorConfig {
    pub allow_self_signed: bool,
    pub validate_expiration: bool,
    pub validate_domain: bool,
    pub verify_certificate_chain: bool,
    pub server_name: ServerName<'static>,
}

impl PkiValidatorConfig {
    fn new(config: &impl PkiValidatorConfiguration) -> Self {
        Self {
            allow_self_signed: config.get_allow_self_signed_certificate(),
            validate_expiration: config.get_validate_expiration(),
            validate_domain: config.get_validate_domain(),
            verify_certificate_chain: config.get_validate_certificate_chain(),
            server_name: ServerName::try_from(config.get_domain()).unwrap(),
        }
    }
}

pub struct PkiValidator {
    config: PkiValidatorConfig,
    cert_chain_verifier: Verifier,
}
impl PkiValidator {
    pub fn new(config: PkiValidatorConfig) -> Self {
        Self {
            config,
            cert_chain_verifier: Default::default(),
        }
    }
}

impl PkiValidator {
    fn verify_certificate<'a>(
        &self,
        certificate: &X509Certificate,
        intermediate: Vec<X509Certificate<'a>>,
    ) -> Result<(), ValidateCertificateError> {
        if self.config.allow_self_signed {
            if !is_self_signed(certificate) {
                return Err(ValidateCertificateError::CertificateSelfSigned);
            }
        }
        if self.config.validate_domain {
            if !validate_certificate_domain(certificate, &self.config.server_name) {
                return Err(ValidateCertificateError::NonMatchingServerName(
                    certificate.subject.to_string(),
                    self.config.server_name.to_str().to_string(),
                ));
            }
        }

        if self.config.validate_expiration {
            if is_certificate_expired(certificate) {
                return Err(ValidateCertificateError::CertificateHasExpired);
            }
        }

        if self.config.verify_certificate_chain {
            if !validate_certificate_chain(
                &self.cert_chain_verifier,
                certificate,
                &intermediate,
                &self.config.server_name,
            ) {
                return Err(ValidateCertificateError::InvalidCertificateChain);
            }
        }
        return Ok(());
    }

    fn verify_identity(&self, identity: &Identity) -> Result<(), ValidateCertificateError> {
        if !validate_signature(&identity.certificate, &identity.private_key) {
            return Err(ValidateCertificateError::InvalidCertificateSignature);
        }

        if !validate_certificate_domain(&identity.certificate, &identity.server_name) {
            return Err(ValidateCertificateError::NonMatchingServerName(
                identity.certificate.subject.to_string(),
                identity.server_name.to_str().to_string(),
            ));
        }
        let mut temp_intermediate = identity.intermediate.clone();
        temp_intermediate.push(identity.ca_certificate.clone());
        if !validate_certificate_chain(
            &self.cert_chain_verifier,
            &identity.certificate,
            &temp_intermediate,
            &identity.server_name,
        ) {
            return return Err(ValidateCertificateError::InvalidCertificateChain);
        }
        Ok(())
    }
}
