#![feature(slice_pattern)]
extern crate core;

k8s_openapi::k8s_if_le_1_26! {
    compile_error!("This crate requires the v1_26 (or higher) feature to be enabled on the k8s-openapi crate.");
}


use rustls_pki_types::{
    CertificateDer, CertificateRevocationListDer, CertificateSigningRequestDer, PrivateKeyDer,
    PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer, ServerName,
};
use x509_parser::certificate::X509Certificate;

pub mod configuration;
pub mod generic_private_key;
pub mod parser;
pub mod store;
pub mod validate;
// Kubernetes cert-manager ask Let's Encrypt for pki for website domain.
// The pki is stored in a kubernetes Secret
// We load in the secret and parse it then validate the pki in PEM format.
// After of witch we perform pki validation such as:
//- Certificate Validity: Ensures the pki is not expired and is issued by a trusted CA.
//- Hostname Matching: Checks that the domain name in the pki matches the domain of the configuration
//- Certificate Chain: Validates the pki chain up to a trusted root CA.
// After validating the pki, we watch for kubernetes changes over the secret.

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

pub trait IdentityValidator {
    fn is_valid(&self, identity: Identity) -> bool;
}

#[derive(Debug)]
pub struct ParsedPkiData<'a> {
    pub x509: Vec<CertificateDer<'a>>,
    pub pkc1: Vec<PrivatePkcs1KeyDer<'a>>,
    pub sec1: Vec<PrivateSec1KeyDer<'a>>,
    pub crls: Vec<CertificateRevocationListDer<'a>>,
    pub csrs: Vec<CertificateSigningRequestDer<'a>>,
    pub pkcs8: Vec<PrivatePkcs8KeyDer<'a>>,
}

impl<'a> ParsedPkiData<'a> {
    pub fn merge<'b>(&mut self, other: &mut ParsedPkiData<'b>)
    where
        'a: 'b,
        'b: 'a,
    {
        self.crls.append(&mut other.crls);
        self.csrs.append(&mut other.csrs);
        self.x509.append(&mut other.x509);
        self.sec1.append(&mut other.sec1);
        self.pkc1.append(&mut other.pkc1);
        self.pkcs8.append(&mut other.pkcs8);
    }
}

impl Default for ParsedPkiData<'_> {
    fn default() -> Self {
        Self {
            x509: vec![],
            pkc1: vec![],
            sec1: vec![],
            crls: vec![],
            csrs: vec![],
            pkcs8: vec![],
        }
    }
}

impl Identity<'_> {
    /// Returns the server certificate, intermediate certificates and CA's certificate.
    fn get_certificate_chain(&self) -> Vec<X509Certificate> {
        let mut certificate_chain = Vec::new();
        certificate_chain.push(self.certificate.clone());
        certificate_chain.append(&mut self.intermediate.clone());
        certificate_chain.push(self.ca_certificate.clone());
        certificate_chain
    }
}
