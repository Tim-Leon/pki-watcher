use crate::validate::validate::{is_certificate_expired, is_self_signed};
use rustls_pki_types::{PrivateKeyDer, ServerName};
use x509_parser::certificate::X509Certificate;

// The server identity, used to prove that it's the server, must hold private key,
#[derive(Debug)]
pub struct Identity<'a> {
    /// Server name, parsed from certificate subject. Used to identify and verify certificate target.
    pub server_name: ServerName<'a>,
    /// This server certificate.
    pub certificate: X509Certificate<'a>,
    /// The private key for the certificate.
    pub private_key: PrivateKeyDer<'a>,
    /// The intermediate certificate between certificate and ca_certificate
    pub intermediate: Vec<X509Certificate<'a>>,
    /// CA's certificate is normally pre-installed on a client as a trust anchor.
    pub ca_certificate: X509Certificate<'a>,
}

pub trait Identities {
    /// Checks if any of the certificates in the chain are self-signed.
    fn is_any_self_signed(&self) -> bool;
    /// Checks if any of the certificates in the chain are expired.
    fn is_any_expired(&self) -> bool;
    /// Returns the server certificate, intermediate certificates and CA's certificate.
    fn get_certificate_chain(&self) -> Vec<X509Certificate>;
}

impl Identities for Identity<'_> {
    fn is_any_self_signed(&self) -> bool {
        for cert in &self.get_certificate_chain() {
            if is_self_signed(cert) {
                return true;
            }
        }
        false
    }

    fn is_any_expired(&self) -> bool {
        for cert in &self.get_certificate_chain() {
            if is_certificate_expired(cert) {
                return true;
            }
        }
        false
    }

    fn get_certificate_chain(&self) -> Vec<X509Certificate> {
        let mut certificate_chain = Vec::new();
        certificate_chain.push(self.certificate.clone());
        certificate_chain.append(&mut self.intermediate.clone());
        certificate_chain.push(self.ca_certificate.clone());
        certificate_chain
    }
}
