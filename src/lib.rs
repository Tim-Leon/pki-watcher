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
use crate::identity::Identity;

pub mod configuration;
pub mod generic_private_key;
pub mod parser;
pub mod store;
pub mod validate;
pub mod identity;
// Kubernetes cert-manager ask Let's Encrypt for pki for website domain.
// The pki is stored in a kubernetes Secret
// We load in the secret and parse it then validate the pki in PEM format.
// After of witch we perform pki validation such as:
//- Certificate Validity: Ensures the pki is not expired and is issued by a trusted CA.
//- Hostname Matching: Checks that the domain name in the pki matches the domain of the configuration
//- Certificate Chain: Validates the pki chain up to a trusted root CA.
// After validating the pki, we watch for kubernetes changes over the secret.



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

