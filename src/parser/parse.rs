use core::slice::SlicePattern;
use std::{
    io::{BufRead, Cursor},
    iter,
};
use std::collections::HashMap;

use der::{Decode, Encode};
use k8s_openapi::api::core::v1::Secret;
use pkcs1::RsaPrivateKey;
use rustls_pemfile::read_one;
use rustls_pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivateSec1KeyDer,
    ServerName,
};
use spiffe::svid::x509::X509Svid;
use x509_parser::{certificate::X509Certificate, error::X509Error, nom::Parser, x509::X509Version};
use x509_parser::prelude::X509CertificateParser;
use x509_parser::public_key::{PublicKey, RSAPublicKey};

use crate::{Identity, ParsedPkiData};
use crate::parser::{IdentityParser, PemParser};

#[derive(thiserror::Error, Debug)]
pub enum ParseKubernetesPemSecreteError {
    #[error(transparent)]
    DecodePemError(#[from] PemParseError),
    #[error("InvalidData")]
    InvalidData,
    #[error("InvalidKey")]
    InvalidKey,
}
#[derive(Debug, thiserror::Error)]
pub enum KubernetesError {}
pub fn parse_kubernetes_secret<'a>(
    secret: &'a Secret,
    key: &'a str,
) -> Result<Cursor<&'a [u8]>, ParseKubernetesPemSecreteError> {
    let data = match &secret.data {
        Some(data) => data,
        None => {
            return Err(ParseKubernetesPemSecreteError::InvalidData);
        }
    };

    let reader = match data.get(key) {
        Some(cert_data) => Cursor::new(cert_data.0.as_slice()),
        None => {
            return Err(ParseKubernetesPemSecreteError::InvalidKey);
        }
    };
    Ok(reader)
}

//pub struct EllipticCurveKeyPair {
//    pub ec_public_key: PublicKey<>,
//    pub ec_private_key: SecretKey<>,
//}

#[derive(thiserror::Error, Debug)]
pub enum DecodePemError {
    #[error("UnsupportedX509Version")]
    UnsupportedX509Version,
    #[error(transparent)]
    ParseCertificateError(#[from] X509Error),
    #[error(transparent)]
    ParsePkcs8Error(#[from] pkcs8::Error),
    #[error(transparent)]
    ParsePkcs1Error(#[from] rsa::pkcs1::Error),

    #[error("UnknownDerEncodedItem")]
    UnknownDerEncodedItem,
    #[error("FailedToReadDerEncodedItem")]
    FailedToReadDerEncodedItem,
}

#[derive(Clone, Debug)]
pub struct PkiParser {
    x509certificate_parser: X509CertificateParser,
}

impl PkiParser {
    pub fn new() -> Self {
        let x509certificate_parser = X509CertificateParser::new();
        Self {
            x509certificate_parser,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum PemParseError {
    #[error("UnsupportedX509Version")]
    UnsupportedX509Version,
    #[error("UnknownDerEncodedItem")]
    UnknownDerEncodedItem,
    #[error("FailedToReadDerEncodedItem")]
    FailedToReadDerEncodedItem,
    #[error("UnsupportedCertificateEncryptionScheme")]
    UnsupportedCertificateEncryptionScheme,
    #[error(transparent)]
    ParseX509Error(#[from] X509Error),
}
#[derive(Debug, thiserror::Error)]
pub enum SvidParsingError {
    #[error("EmptyInput")]
    EmptyInput,
}
//#[async_trait]
impl PkiParser {
    pub fn parse_pem(
        &mut self,
        source: &mut ParsedPkiData,
        mut reader: impl BufRead,
    ) -> Result<(), PemParseError> {
        let mut identities = Vec::<Identity>::new();
        for item in iter::from_fn(|| read_one(&mut reader).transpose()) {
            match item {
                Ok(item) => match item {
                    rustls_pemfile::Item::X509Certificate(x509) => {
                        source.x509.push(x509);
                    }
                    rustls_pemfile::Item::Pkcs1Key(pkc1) => {
                        source.pkc1.push(pkc1);
                    }
                    rustls_pemfile::Item::Pkcs8Key(pkcs8) => source.pkcs8.push(pkcs8),
                    rustls_pemfile::Item::Sec1Key(sec1) => {
                        source.sec1.push(sec1);
                    }
                    rustls_pemfile::Item::Crl(crl) => {
                        source.crls.push(crl);
                    }
                    rustls_pemfile::Item::Csr(csr) => {
                        source.csrs.push(csr);
                    }
                    _ => return Err(PemParseError::UnknownDerEncodedItem),
                },
                Err(_) => return Err(PemParseError::FailedToReadDerEncodedItem),
            }
        }
        Ok(())
    }

    pub fn parse_x509_svid<'a, 'b: 'a>(
        &mut self,
        source: &mut Identities<'a>,
        svid: &'a X509Svid,
    ) -> Result<(), SvidParsingError> {
        use x509_parser::prelude::FromDer;
        let cert_chain = svid.cert_chain();
        if cert_chain.is_empty() {
            return Err(SvidParsingError::EmptyInput);
        }

        let mut certificate: Option<X509Certificate> = None;
        let mut intermediate: Vec<X509Certificate> = vec![];
        let mut ca_certificate: Option<X509Certificate> = None;
        for (index, cert) in cert_chain.iter().enumerate() {
            let (bytes, x509) = X509Certificate::from_der(cert.content()).unwrap();
            if index == 0 {
                certificate = Some(x509.clone());
            } else if index != cert_chain.len() {
                ca_certificate = Some(x509.clone());
            } else {
                intermediate.push(x509.clone())
            }
        }

        let prv = PrivateKeyDer::try_from(svid.private_key().content()).unwrap();

        let server_name =
            ServerName::try_from(certificate.clone().unwrap().subject.to_string()).unwrap();
        let identity = Identity {
            server_name,
            certificate: certificate.unwrap(),
            private_key: prv,
            intermediate,
            ca_certificate: ca_certificate.unwrap(),
        };
        source.inner.push(identity);
        Ok(())
    }
}
fn parse_x509_der<'a>(
    x509_parser: &'a mut X509CertificateParser,
    der: &'a CertificateDer<'a>,
) -> Result<X509Certificate<'a>, PemParseError> {
    let (raw, cert) = x509_parser.parse(der).unwrap();
    if cert.tbs_certificate.version != X509Version::V3 {
        return Err(PemParseError::UnsupportedX509Version);
    }
    Ok(cert)
}
#[derive(thiserror::Error, Debug)]
pub enum IdentityParserError {
    #[error("UnsupportedCertificateEncryptionScheme")]
    UnsupportedCertificateEncryptionScheme,
}

pub fn check_for_certificate_private_key() {}

impl IdentityParser for PkiParser {
    type Error = IdentityParserError;

    fn intermediate_certificates(
        &self,
        source: &X509Certificate,
        intermediate_certificates: &Vec<X509Certificate>,
    ) -> Result<Vec<X509Certificate>, Self::Error> {
        let mut target_intermidate_certificates = Vec::new();
        for inter in intermediate_certificates {
            if source == inter {
                todo!();
                target_intermidate_certificates.push(inter.clone());
            }
        }
        Ok(target_intermidate_certificates)
    }

    fn ca_certificate(
        &self,
        source: &X509Certificate,
        potential_ca_certificate: &Vec<X509Certificate>,
    ) -> Result<X509Certificate, Self::Error> {
        todo!()
    }

    fn certificate_chain(
        &self,
        source: &X509Certificate,
        intermediate_certificates: &Vec<CertificateDer>,
        ca_certificate: &Vec<CertificateDer>,
    ) -> Result<(Vec<X509Certificate>, X509Certificate), Self::Error> {
        todo!()
    }

    fn parse_identity<'a>(
        &'a self,
        pki_data_source: &'a ParsedPkiData<'a>,
        identities: &mut Identities<'a>,
    ) -> Result<(), Self::Error> {
        use x509_parser::prelude::FromDer;

        let mut intermediate_certificates: Vec<CertificateDer> = Vec::new();
        for (x, potential_intermediate_certificate) in pki_data_source
            .x509
            .iter()
            .map(|x| X509Certificate::from_der(x).unwrap())
        {
            if potential_intermediate_certificate.is_ca() {
                intermediate_certificates.push(CertificateDer::from(x));
            }
        }
        let ca_certificate: Vec<CertificateDer> = Vec::new();

        for (data, certificate) in pki_data_source
            .x509
            .iter()
            .map(|x| X509Certificate::from_der(x).unwrap())
        {
            let alg = certificate.public_key().algorithm.clone();
            //if alg.parameters.is_some() {
            //    // Do not parse certificate with specific keys with additional parameters
            //    continue;
            //}
            match certificate.public_key().parsed().unwrap() {
                PublicKey::RSA(rsa) => {
                    for private_key in pki_data_source
                        .pkc1
                        .iter()
                        .map(|x| RsaPrivateKey::from_der(x.secret_pkcs1_der()).unwrap())
                    {
                        let temp_public =
                            RsaPrivateKey::from_der(private_key.to_der().unwrap().as_slice())
                                .unwrap()
                                .public_key()
                                .to_der()
                                .unwrap();
                        let (data, public_key) =
                            RSAPublicKey::from_der(temp_public.as_slice()).unwrap();
                        if rsa == public_key {
                            let (intermediate, ca) = self.certificate_chain(
                                &certificate,
                                &intermediate_certificates,
                                &ca_certificate,
                            )?;

                            let identity = Identity {
                                server_name: ServerName::try_from(
                                    certificate.subject.to_string().as_str(),
                                )
                                    .unwrap()
                                    .to_owned(),
                                certificate: certificate.clone(),
                                private_key: PrivateKeyDer::try_from(PrivatePkcs1KeyDer::from(
                                    private_key.to_der().unwrap(),
                                ))
                                    .unwrap(),
                                intermediate,
                                ca_certificate: ca,
                            };

                            identities.push(identity);
                        }
                    }
                }
                PublicKey::EC(ec) => {
                    for private_key in pki_data_source.sec1
                        .iter()
                        .map(|x| sec1::EcPrivateKey::from_der(x.secret_sec1_der()).unwrap())
                    {
                        //TODO: Fix
                        //let temp_public = elliptic_curve::PublicKey::from_sec1_bytes(ec.data()).unwrap();
                        //let temp_public = sec1::EcPrivateKey::from_der(ec.data()).unwrap().public_key.unwrap();
                        let temp_public = private_key.public_key.unwrap();
                        if ec.data() == temp_public {
                            let (intermediate, ca) = self.certificate_chain(
                                &certificate,
                                &intermediate_certificates,
                                &ca_certificate,
                            )?;
                            let identity = Identity {
                                server_name: ServerName::try_from(certificate.subject.to_string().as_str()).unwrap().to_owned(),
                                certificate: certificate.clone(),
                                private_key: PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(private_key.to_der().unwrap())),
                                intermediate,
                                ca_certificate: ca,
                            };
                            identities.push(identity);
                        }
                    }
                }
                PublicKey::DSA(dsa) => continue,
                PublicKey::GostR3410(_) => continue,
                PublicKey::GostR3410_2012(_) => continue,
                PublicKey::Unknown(_) => continue,
            };
        }
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct Identities<'a> {
    pub inner: Vec<Identity<'a>>,
    pub map: HashMap<ServerName<'a>, &'a Identity<'a>>,
}

impl<'a> Identities<'a> {
    pub fn new(identities: Vec<Identity<'a>>) -> Self {
        let mut map = HashMap::<ServerName<'a>, &'a Identity<'a>>::new();
        for identity in &identities {
            // Use the same lifetime as the identities vector for the references
            let identity_ref: &'a Identity<'a> = unsafe { &*(identity as *const _) };
            map.insert(identity.server_name.clone(), identity_ref);
        }
        Self {
            inner: identities,
            map,
        }
    }

    pub fn get_identity(&self, key: &ServerName<'a>) -> Option<&&Identity<'a>> {
        self.map.get(key)
    }

    pub fn push(&mut self, identity: Identity<'a>) {
        self.inner.push(identity)
    }

    pub fn remove(&mut self, index: usize) {
        self.inner.remove(index);
    }
}
