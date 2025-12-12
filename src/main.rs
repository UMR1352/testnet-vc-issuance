use anyhow::Context;
use identity_iota::core::FromJson;
use identity_iota::core::Object;
use identity_iota::core::Url;
use identity_iota::core::json;
use identity_iota::credential::CredentialBuilder;
use identity_iota::credential::CredentialV2;
use identity_iota::credential::EnvelopedVc;
use identity_iota::credential::FailFast;
use identity_iota::credential::Jwt;
use identity_iota::credential::JwtCredentialValidationOptions;
use identity_iota::credential::JwtCredentialValidator;
use identity_iota::credential::JwtPresentationOptions;
use identity_iota::credential::JwtPresentationValidationOptions;
use identity_iota::credential::JwtPresentationValidator;
use identity_iota::credential::JwtVcV2;
use identity_iota::credential::Presentation;
use identity_iota::credential::PresentationBuilder;
use identity_iota::credential::RevocationBitmapStatus;
use identity_iota::credential::Status;
use identity_iota::credential::Subject;
use identity_iota::did::DID;
use identity_iota::iota::IotaDocument;
use identity_iota::iota::rebased::client::IdentityClientReadOnly;
use identity_iota::prelude::IotaDID;
use identity_iota::storage::JwkDocumentExt;
use identity_iota::storage::JwkStorage;
use identity_iota::storage::JwsSignatureOptions;
use identity_iota::storage::KeyIdStorage;
use identity_iota::storage::MethodDigest;
use identity_iota::storage::Storage;
use identity_iota::verification::jwk::Jwk;
use iota_sdk::IotaClientBuilder;
use jws_verifier::EdECDSAVerifier;
use memstore::JwkMemStore;
use memstore::KeyIdMemStore;

type MemStorage = Storage<JwkMemStore, KeyIdMemStore>;

mod jws_verifier;
mod memstore;

const ISSUER_SK_JWK_ED25519: &str = r#"{"kty":"OKP","alg":"EdDSA","crv":"Ed25519","x":"Fu14kRcyKvkq8rwkpjeCQib1cMnzffABKt3bqDku0QY","d":"tAkoWykqE1d7a4_oPK34O-f3sipoZs5cocs1X1OrSvc"}"#;
const ISSUER_SK_JWK_SECP256R1: &str = r#"{"kty":"EC","alg":"ES256","crv":"P-256","x":"-_-Mk1gKHKQ1xB1HK_rn0zrI0Oi7F3U8ikmL68NAizs","y":"O7eZWQN39LEqoPj7ANjedWxPwz4kyENeZz0Wee7rvIg","d":"Y_mxnJhvDSVxIA7sqYhWqiLaljF6DEiKnJwtmkSUsiw"}"#;
const ISSUER_SK_JWK_SECP256K1: &str = r#"{"kty":"EC","alg":"ES256K","crv":"secp256k1","x":"xG44UKSdX8mM80WLW1cWQj2-c7IOXTZSotcua11ziIc","y":"fQf8Yl5L2ZcLoMjIBKiJ7IQviAWCgpASJVLiUJfs1Ko","d":"QTz06zFX9ZCV_hsgEwWrACuDuOXZ9YFF8QrAqdOgK6E"}"#;
const ISSUER_DID: &str =
    "did:iota:testnet:0x7db4221efeb1ade76a54aef3af9e3410ce0c8ea5fc12b45bb7a348e0c465ec41";

const HOLDER_SK_JWK: &str = r#"{"kty":"OKP","alg":"EdDSA","crv":"Ed25519","x":"lJExsgg-WgGc9fBMC61YOjYmWvc19K3DlHv96baFAso","d":"QTR8_ZP5c2LsK7Pup-akOWkSBlnAo5DWr5mBbMF5avw"}"#;
const HOLDER_DID: &str =
    "did:iota:testnet:0x3d5da894b57b586781737dd82af550d3244b1d9be9400cc8d0eb2ad84c3bff29";
const CREDENTIAL_REVOCATION_INDEX: u32 = 42;

async fn make_issuer(key_store: &MemStorage) -> anyhow::Result<IotaDocument> {
    let iota_client = IotaClientBuilder::default().build_testnet().await?;
    let identity_client = IdentityClientReadOnly::new(iota_client).await?;

    let did_document = identity_client
        .resolve_did(&IotaDID::parse(ISSUER_DID)?)
        .await?;

    // Feel storage with the hardcoded keys.
    for (i, jwk) in [
        Jwk::from_json(ISSUER_SK_JWK_ED25519)?,
        Jwk::from_json(ISSUER_SK_JWK_SECP256R1)?,
        Jwk::from_json(ISSUER_SK_JWK_SECP256K1)?,
    ]
    .into_iter()
    .enumerate()
    {
        let vm = did_document
            .resolve_method(&format!("key-{i}"), None)
            .unwrap();
        let key_id = key_store.key_storage().insert(jwk).await?;
        key_store
            .key_id_storage()
            .insert_key_id(MethodDigest::new(vm)?, key_id)
            .await?;
    }

    Ok(did_document)
}

async fn make_holder(key_store: &MemStorage) -> anyhow::Result<(IotaDocument, String)> {
    let iota_client = IotaClientBuilder::default().build_testnet().await?;
    let identity_client = IdentityClientReadOnly::new(iota_client).await?;

    let sk_jwk = Jwk::from_json(HOLDER_SK_JWK)?;

    let did_document = identity_client
        .resolve_did(&IotaDID::parse(HOLDER_DID)?)
        .await?;
    let vm = did_document.methods(None)[0];
    let fragment = vm.id().fragment().expect("fragment is set").to_owned();

    let key_id = key_store.key_storage().insert(sk_jwk).await?;
    key_store
        .key_id_storage()
        .insert_key_id(MethodDigest::new(vm)?, key_id.clone())
        .await?;

    Ok((did_document, fragment))
}

async fn issue_credential(
    issuer_document: &IotaDocument,
    issuer_fragment: &str,
    storage: &MemStorage,
) -> anyhow::Result<JwtVcV2> {
    let subject = Subject::from_json_value(json!({
      "id": HOLDER_DID,
      "name": "Alice",
      "degree": {
        "type": "BachelorDegree",
        "name": "Bachelor of Science and Arts",
      },
      "GPA": "4.0",
    }))?;

    let service_url = issuer_document
        .id()
        .to_url()
        .join("#my-revocation-service")?;
    let status: Status =
        RevocationBitmapStatus::new(service_url, CREDENTIAL_REVOCATION_INDEX).into();

    // Build credential using subject above and issuer.
    let credential: CredentialV2 = CredentialBuilder::default()
        .id(Url::parse("https://example.edu/credentials/3732")?)
        .issuer(Url::parse(issuer_document.id().as_str())?)
        .type_("UniversityDegreeCredential")
        .status(status)
        .subject(subject)
        .build_v2()?;

    println!("Credential JSON > {credential:#}");

    let credential_jwt = issuer_document
        .create_credential_v2_jwt(
            &credential,
            storage,
            issuer_fragment,
            &JwsSignatureOptions::default(),
        )
        .await?;

    Ok(credential_jwt)
}

async fn make_jwt_presentation(
    jwt_credential: JwtVcV2,
    holder_document: &IotaDocument,
    key_store: &MemStorage,
    fragment: &str,
) -> anyhow::Result<Jwt> {
    let presentation = PresentationBuilder::new(
        Url::parse(holder_document.id().as_str()).expect("a DID is a valid URL"),
        Object::default(),
    )
    .credential(jwt_credential.into_enveloped_vc())
    .build_v2()?;

    holder_document
        .create_presentation_jwt(
            &presentation,
            key_store,
            fragment,
            &JwsSignatureOptions::default(),
            &JwtPresentationOptions::default(),
        )
        .await
        .context("failed create a JWT out of this verifiable presentation")
}

async fn validate_presentation(
    jwt_presentation: &Jwt,
    issuer_document: &IotaDocument,
    holder_document: &IotaDocument,
) -> anyhow::Result<()> {
    let presentation: Presentation<EnvelopedVc, Object> =
        JwtPresentationValidator::with_signature_verifier(EdECDSAVerifier)
            .validate(
                jwt_presentation,
                holder_document,
                &JwtPresentationValidationOptions::default(),
            )?
            .presentation;

    let credential_validator = JwtCredentialValidator::with_signature_verifier(EdECDSAVerifier);
    for maybe_jwt_credential in presentation
        .verifiable_credential
        .into_iter()
        .map(EnvelopedVc::try_into)
    {
        credential_validator.validate_v2::<_, Object>(
            &maybe_jwt_credential?,
            issuer_document,
            &JwtCredentialValidationOptions::default(),
            FailFast::FirstError,
        )?;
    }

    println!("Presentation validated successfully!!!");

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let key_store = Storage::new(JwkMemStore::default(), KeyIdMemStore::default());
    let issuer_document = make_issuer(&key_store).await?;
    // key-0 -> ed25519,
    // key-1 -> secp256r1,
    // key-2 -> secp256k1,
    let issuer_fragment = "key-0";
    let (holder_document, holder_fragment) = make_holder(&key_store).await?;

    let jwt_credential = issue_credential(&issuer_document, issuer_fragment, &key_store).await?;
    println!("Issued Credential JWT > {}", jwt_credential.as_str());

    let jwt_presentation = make_jwt_presentation(
        jwt_credential,
        &holder_document,
        &key_store,
        &holder_fragment,
    )
    .await?;
    println!("Presentation JWT > {}", jwt_presentation.as_str());

    validate_presentation(&jwt_presentation, &issuer_document, &holder_document).await?;

    Ok(())
}
