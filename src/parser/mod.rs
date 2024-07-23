use std::io::BufRead;

use async_trait::async_trait;
use pkcs1::RsaPrivateKey;
use pkcs8::PrivateKeyInfo;
use rustls_pki_types::{
    CertificateDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use sec1::EcPrivateKey;
use x509_parser::certificate::X509CertificateParser;
use x509_parser::prelude::X509Certificate;

use crate::ParsedPkiData;
use crate::parser::parse::Identities;

pub mod parse;

#[async_trait]
pub trait PemParser {
    type Error;
    fn parse_pem(&mut self, reader: impl BufRead) -> Result<ParsedPkiData, Self::Error>;

    fn parse_pkcs1_der<'a>(
        &self,
        der: PrivatePkcs1KeyDer<'a>,
    ) -> Result<RsaPrivateKey, Self::Error>;

    fn parse_sec1_der<'a>(&self, der: PrivateSec1KeyDer<'a>) -> Result<EcPrivateKey, Self::Error>;

    fn parse_pkcs8_der<'a>(
        &self,
        der: PrivatePkcs8KeyDer<'a>,
    ) -> Result<PrivateKeyInfo, Self::Error>;

    fn parse_x509_der<'a>(
        x509_parser: &'a mut X509CertificateParser,
        der: CertificateDer,
    ) -> Result<X509Certificate<'a>, Self::Error>;
}

pub trait IdentityParser {
    type Error;

    // Returns a list of intermediate certificates, from the po
    fn intermediate_certificates(
        &self,
        source: &X509Certificate,
        potential_intermediate_certificates: &Vec<X509Certificate>,
    ) -> Result<Vec<X509Certificate>, Self::Error>;
    // Returns the CA certificate.
    fn ca_certificate(
        &self,
        source: &X509Certificate,
        potential_ca_certificate: &Vec<X509Certificate>,
    ) -> Result<X509Certificate, Self::Error>;

    // Returns a list of intermediate certificates and ca certificate.
    fn certificate_chain(
        &self,
        source: &X509Certificate,
        potential_intermediate_certificates: &Vec<CertificateDer>,
        potential_ca_certificate: &Vec<CertificateDer>,
    ) -> Result<(Vec<X509Certificate>, X509Certificate), Self::Error>;

    /// The name is the Domain or Ip Address of the certificate.
    fn parse_identity<'a>(
        &'a self,
        pki_data_source: &'a ParsedPkiData<'a>,
        identities: &mut Identities<'a>,
    ) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::configuration::FilePkiStoreConfiguration;
    use crate::ParsedPkiData;
    use crate::parser::IdentityParser;
    use crate::parser::parse::{Identities, PkiParser};

    struct TestConfig {
        pub file_path: String,
        pub watch_file: bool,
    }
    impl FilePkiStoreConfiguration for TestConfig {
        fn get_file_path(&self) -> String {
            self.file_path.clone()
        }

    }

    #[test]
    fn test_parsing_sec() {
        let mut parsed_pki_data = ParsedPkiData::default();
        let mut pki_parser = PkiParser::new();

        {
            let certificate = include_bytes!("../../tests/data/www-google-com-chain.pem");
            let buf = Cursor::new(certificate);
            pki_parser.parse_pem(&mut parsed_pki_data, buf).unwrap();
        }

        {
            let certificate = include_bytes!("../../tests/data/rsa.pem");
            let buf = Cursor::new(certificate);
            pki_parser.parse_pem(&mut parsed_pki_data, buf).unwrap();

        }
        // TODO: Fix the test, currently no private keys are included, resulting in zero identities being parsed.
        let mut identities = Identities::default();
        pki_parser.parse_identity(&mut parsed_pki_data, &mut identities).unwrap();
        println!("{:?}", identities);
    }


}
