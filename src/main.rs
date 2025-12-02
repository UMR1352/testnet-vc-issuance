use identity_iota::core::FromJson;
use identity_iota::core::Url;
use identity_iota::core::json;
use identity_iota::credential::CredentialBuilder;
use identity_iota::credential::CredentialV2;
use identity_iota::credential::JwtVcV2;
use identity_iota::credential::RevocationBitmapStatus;
use identity_iota::credential::Status;
use identity_iota::credential::Subject;
use identity_iota::did::DID;
use identity_iota::iota::IotaDocument;
use identity_iota::iota::rebased::client::IdentityClient;
use identity_iota::iota::rebased::client::IdentityClientReadOnly;
use identity_iota::prelude::IotaDID;
use identity_iota::storage::JwkDocumentExt;
use identity_iota::storage::JwkMemStore;
use identity_iota::storage::JwkStorage;
use identity_iota::storage::JwsSignatureOptions;
use identity_iota::storage::KeyIdMemstore;
use identity_iota::storage::KeyIdStorage;
use identity_iota::storage::MethodDigest;
use identity_iota::storage::Storage;
use identity_iota::storage::StorageSigner;
use identity_iota::verification::jwk::Jwk;
use iota_sdk::IotaClientBuilder;

type MemStorage = Storage<JwkMemStore, KeyIdMemstore>;
type MemStoreSigner<'a> = StorageSigner<'a, JwkMemStore, KeyIdMemstore>;

const ISSUER_SK_JWK: &str = r#"{"kty":"OKP","alg":"EdDSA","crv":"Ed25519","x":"Fu14kRcyKvkq8rwkpjeCQib1cMnzffABKt3bqDku0QY","d":"tAkoWykqE1d7a4_oPK34O-f3sipoZs5cocs1X1OrSvc"}"#;
const ISSUER_DID: &str =
    "did:iota:testnet:0x7db4221efeb1ade76a54aef3af9e3410ce0c8ea5fc12b45bb7a348e0c465ec41";

const _HOLDER_SK_JWK: &str = r#"{"kty":"OKP","alg":"EdDSA","crv":"Ed25519","x":"lJExsgg-WgGc9fBMC61YOjYmWvc19K3DlHv96baFAso","d":"QTR8_ZP5c2LsK7Pup-akOWkSBlnAo5DWr5mBbMF5avw"}"#;
const HOLDER_DID: &str =
    "did:iota:testnet:0x3d5da894b57b586781737dd82af550d3244b1d9be9400cc8d0eb2ad84c3bff29";
const CREDENTIAL_REVOCATION_INDEX: u32 = 42;

async fn make_issuer(
    key_store: &MemStorage,
) -> anyhow::Result<(IdentityClient<MemStoreSigner<'_>>, IotaDocument, String)> {
    let iota_client = IotaClientBuilder::default().build_testnet().await?;
    let identity_client = IdentityClientReadOnly::new(iota_client).await?;

    let sk_jwk = Jwk::from_json(ISSUER_SK_JWK)?;
    let pk_jwk = sk_jwk
        .to_public()
        .expect("ed25519 keys have public and private components");

    let did_document = identity_client
        .resolve_did(&IotaDID::parse(ISSUER_DID)?)
        .await?;
    let vm = did_document.methods(None)[0];
    let fragment = vm.id().fragment().expect("fragment is set").to_owned();

    let key_id = key_store.key_storage().insert(sk_jwk).await?;
    key_store
        .key_id_storage()
        .insert_key_id(MethodDigest::new(vm)?, key_id.clone())
        .await?;

    let signer = MemStoreSigner::new(key_store, key_id, pk_jwk);
    let identity_client = IdentityClient::new(identity_client, signer).await?;

    Ok((identity_client, did_document, fragment))
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
            &storage,
            &issuer_fragment,
            &JwsSignatureOptions::default(),
        )
        .await?;

    Ok(credential_jwt)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let key_store = Storage::new(JwkMemStore::new(), KeyIdMemstore::new());
    let (_issuer_client, issuer_document, issuer_fragment) = make_issuer(&key_store).await?;

    let jwt_credential = issue_credential(&issuer_document, &issuer_fragment, &key_store).await?;
    println!("Issued Credential JWT > {}", jwt_credential.as_str());

    Ok(())
}
