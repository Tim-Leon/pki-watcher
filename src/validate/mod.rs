pub mod validate;

pub trait PkiValidatorConfiguration {
    fn get_allow_self_signed_certificate(&self) -> bool;

    fn get_validate_expiration(&self) -> bool;

    fn get_validate_domain(&self) -> bool;

    fn get_validate_certificate_chain(&self) -> bool;

    fn get_domain(&self) -> String;
}
