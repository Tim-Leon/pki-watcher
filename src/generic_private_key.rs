use der::Decode;
use pkcs8::PrivateKeyInfo;

pub enum GenericPrivateKey<'a> {
    RsaKey(pkcs1::RsaPrivateKey<'a>),
    ECKey(sec1::EcPrivateKey<'a>),
}

#[derive(thiserror::Error, Debug)]
pub enum ParsePkcs8Error {
    #[error(transparent)]
    Error(#[from] pkcs8::Error),
    #[error("invalid oid {0}")]
    InvalidOid(const_oid::ObjectIdentifier),
}

impl<'a> GenericPrivateKey<'a> {
    pub fn form_private_key_info(ai: PrivateKeyInfo<'a>) -> Result<Self, ParsePkcs8Error> {
        return match ai.algorithm.oid {
            pkcs1::ALGORITHM_OID => Ok(GenericPrivateKey::RsaKey::<'a>(
                pkcs1::RsaPrivateKey::from_der(ai.private_key).unwrap(),
            )),
            sec1::ALGORITHM_OID => Ok(GenericPrivateKey::ECKey::<'a>(
                sec1::EcPrivateKey::from_der(ai.private_key).unwrap(),
            )),
            _ => Err(ParsePkcs8Error::InvalidOid(ai.algorithm.oid)),
        };
    }
}
