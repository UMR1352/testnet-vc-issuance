use identity_iota::verification::{
    jwk::Jwk,
    jws::{
        JwsVerifier, SignatureVerificationError, SignatureVerificationErrorKind, VerificationInput,
    },
};

pub struct EdECDSAVerifier;

impl JwsVerifier for EdECDSAVerifier {
    fn verify(
        &self,
        input: VerificationInput,
        public_key: &Jwk,
    ) -> Result<(), SignatureVerificationError> {
        match public_key.alg().expect("alg is set") {
            "EdDSA" => eddsa_jws_verifier::EdDSAJwsVerifier::default().verify(input, public_key),
            "ES256" | "ES256K" => {
                ecdsa_jws_verifier::EcDSAJwsVerifier::default().verify(input, public_key)
            }
            _ => Err(SignatureVerificationError::new(
                SignatureVerificationErrorKind::UnsupportedAlg,
            )),
        }
    }
}
