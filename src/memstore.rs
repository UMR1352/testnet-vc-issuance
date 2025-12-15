use async_trait::async_trait;
use base64ct::Encoding;
use identity_iota::{
    core::{FromJson, ToJson},
    storage::{
        JwkGenOutput, JwkStorage, KeyId, KeyIdStorage, KeyIdStorageError, KeyIdStorageErrorKind,
        KeyIdStorageResult, KeyStorageError, KeyStorageErrorKind, KeyStorageResult, KeyType,
        MethodDigest,
    },
    verification::{jwk::Jwk, jws::JwsAlgorithm},
};
use serde_json::json;
use std::collections::HashMap;
use tokio::sync::RwLock;

#[derive(Debug, Default)]
pub struct JwkMemStore(RwLock<HashMap<String, Jwk>>);

#[async_trait]
impl JwkStorage for JwkMemStore {
    async fn generate(
        &self,
        key_type: KeyType,
        alg: JwsAlgorithm,
    ) -> KeyStorageResult<JwkGenOutput> {
        let jwk = match (key_type.as_str(), alg) {
            ("Ed25519", JwsAlgorithm::EdDSA) => make_ed25519(),
            ("secp256r1", JwsAlgorithm::ES256) => make_secp256r1(),
            ("secp256k1", JwsAlgorithm::ES256K) => make_secp256k1(),
            _ => {
                return Err(KeyStorageError::new(
                    KeyStorageErrorKind::UnsupportedSignatureAlgorithm,
                ));
            }
        };

        let key_id = jwk.thumbprint_sha256_b64();
        let pk_jwk = jwk.to_public().expect("has public components");

        self.0.write().await.insert(key_id.clone(), jwk);

        Ok(JwkGenOutput::new(KeyId::new(key_id), pk_jwk))
    }

    async fn insert(&self, jwk: Jwk) -> KeyStorageResult<KeyId> {
        let key_id = KeyId::new(jwk.thumbprint_sha256_b64());
        self.0.write().await.insert(key_id.to_string(), jwk);

        Ok(key_id)
    }

    async fn exists(&self, key_id: &KeyId) -> KeyStorageResult<bool> {
        Ok(self.0.read().await.contains_key(key_id.as_str()))
    }

    async fn delete(&self, key_id: &KeyId) -> KeyStorageResult<()> {
        self.0.write().await.remove(key_id.as_str());

        Ok(())
    }

    async fn sign(
        &self,
        key_id: &KeyId,
        data: &[u8],
        public_key: &Jwk,
    ) -> KeyStorageResult<Vec<u8>> {
        let sk_jwk = {
            let store = self.0.read().await;
            store
                .get(key_id.as_str())
                .ok_or_else(|| KeyStorageError::new(KeyStorageErrorKind::KeyNotFound))?
                .clone()
        };
        if sk_jwk.alg() != public_key.alg() {
            return Err(KeyStorageErrorKind::KeyAlgorithmMismatch.into());
        }

        let signature = match sk_jwk.alg().expect("alg is set") {
            "EdDSA" => sign_ed25119(&sk_jwk, data),
            "ES256" => sign_secp256r1(&sk_jwk, data),
            "ES256K" => sign_secp256k1(&sk_jwk, data),
            _ => return Err(KeyStorageErrorKind::UnsupportedSignatureAlgorithm.into()),
        };

        Ok(signature)
    }
}

fn make_ed25519() -> Jwk {
    let ed25519_compact::KeyPair { pk, sk } = ed25519_compact::KeyPair::generate();

    Jwk::from_json_value(json!({
        "kty": "OKP",
        "alg": "EdDSA",
        "curve": "Ed25519",
        "x": base64ct::Base64UrlUnpadded::encode_string(&*pk),
        "d": base64ct::Base64UrlUnpadded::encode_string(&*sk),
    }))
    .expect("valid JWK")
}

fn make_secp256r1() -> Jwk {
    Jwk::from_json(&p256::SecretKey::random(&mut rand::thread_rng()).to_jwk_string())
        .expect("valid JWK")
}

fn make_secp256k1() -> Jwk {
    Jwk::from_json(&k256::SecretKey::random(&mut rand::thread_rng()).to_jwk_string())
        .expect("valid JWK")
}

fn sign_ed25119(jwk: &Jwk, data: &[u8]) -> Vec<u8> {
    let params = jwk.try_okp_params().expect("ed25519 is OKP");
    let mut sk_bytes = [0u8; 64];
    base64ct::Base64UrlUnpadded::decode(
        params.d.as_deref().expect("secret component is set"),
        &mut sk_bytes[..32],
    )
    .expect("valid JWK");
    base64ct::Base64UrlUnpadded::decode(&params.x, &mut sk_bytes[32..]).expect("valid JWK");

    let sk = ed25519_compact::SecretKey::from_slice(&sk_bytes).expect("valid ed25519 key");
    sk.sign(data, None).to_vec()
}

fn sign_secp256r1(jwk: &Jwk, data: &[u8]) -> Vec<u8> {
    // p256 JWK parsing is broken, if any property other than the EC-curve specific one are set, deserialization fails.
    // In this case "alg" is set, it has to go.
    let jwk = Jwk::from_params(jwk.params().clone());
    let sk = p256::SecretKey::from_jwk_str(
        &jwk.to_json()
            .inspect(|j| {
                dbg!(j);
            })
            .expect("serialization can't fail"),
    )
    .expect("valid secp256r1 secret key");
    let signing_key = p256::ecdsa::SigningKey::from(sk);
    signing_key.sign_recoverable(data).unwrap().0.to_vec()
}

fn sign_secp256k1(jwk: &Jwk, data: &[u8]) -> Vec<u8> {
    let jwk = Jwk::from_params(jwk.params().clone());
    let sk = k256::SecretKey::from_jwk_str(
        &jwk.to_json()
            .inspect(|j| {
                dbg!(j);
            })
            .expect("serialization can't fail"),
    )
    .expect("valid secp256k1 secret key");
    let signing_key = k256::ecdsa::SigningKey::from(sk);
    signing_key.sign_recoverable(data).unwrap().0.to_vec()
}

#[derive(Debug, Default)]
pub struct KeyIdMemStore(RwLock<HashMap<MethodDigest, String>>);

#[async_trait]
impl KeyIdStorage for KeyIdMemStore {
    async fn insert_key_id(
        &self,
        method_digest: MethodDigest,
        key_id: KeyId,
    ) -> KeyIdStorageResult<()> {
        self.0.write().await.insert(method_digest, key_id.into());

        Ok(())
    }

    async fn get_key_id(&self, method_digest: &MethodDigest) -> KeyIdStorageResult<KeyId> {
        self.0
            .read()
            .await
            .get(method_digest)
            .map(KeyId::new)
            .ok_or_else(|| KeyIdStorageError::new(KeyIdStorageErrorKind::KeyIdNotFound))
    }

    async fn delete_key_id(&self, method_digest: &MethodDigest) -> KeyIdStorageResult<()> {
        self.0.write().await.remove(method_digest);
        Ok(())
    }
}

#[tokio::test]
async fn gen_keys() -> anyhow::Result<()> {
    let mut store = JwkMemStore::default();
    let JwkGenOutput {
        key_id: secp256r1_key_id,
        ..
    } = store
        .generate(KeyType::from_static_str("secp256r1"), JwsAlgorithm::ES256)
        .await?;
    let JwkGenOutput {
        key_id: secp256k1_key_id,
        ..
    } = store
        .generate(KeyType::from_static_str("secp256k1"), JwsAlgorithm::ES256K)
        .await?;

    let (secp256r1_sk, secp256k1_sk) = {
        let store = store.0.get_mut();
        (
            store.get(secp256r1_key_id.as_str()).unwrap(),
            store.get(secp256k1_key_id.as_str()).unwrap(),
        )
    };

    println!(
        "{}\n{}",
        secp256r1_sk.to_json().unwrap(),
        secp256k1_sk.to_json().unwrap()
    );
    panic!();
}
