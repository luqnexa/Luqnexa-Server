// SPDX-License-Identifier: AGPL-3.0-only
//! Local release distribution and explicit word submissions. HTTPS termination
//! and external PostgreSQL/Redis/R2 deployment are not implemented here.
use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use nextime_security::{SignedManifest, VerifyingKey, file_sha256, invalid, sha256};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio_util::io::ReaderStream;
#[derive(Clone)]
pub struct ApiState {
    inner: Arc<Inner>,
}
struct Inner {
    root: PathBuf,
    manifest: SignedManifest,
    token_hash: String,
    serial: Mutex<(Instant, u32, u64)>,
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
impl ApiState {
    pub fn new(root: impl AsRef<Path>, key: VerifyingKey, token: &str) -> io::Result<Self> {
        if token.len() < 32 || token.len() > 256 || !token.is_ascii() {
            return Err(invalid("submission token must be 32..256 ASCII bytes"));
        }
        let root = root.as_ref();
        let meta = root.join("manifest.json");
        if fs::metadata(&meta)?.len() > 8192 {
            return Err(invalid("oversized manifest"));
        }
        let manifest: SignedManifest = serde_json::from_slice(&fs::read(meta)?)?;
        manifest.verify(&key, now())?;
        if file_sha256(root.join("base.nud"))? != manifest.manifest.sha256 {
            return Err(invalid("release hash mismatch"));
        }
        if let Some(delta) = &manifest.manifest.delta {
            if file_sha256(root.join("delta.json"))? != delta.sha256 {
                return Err(invalid("delta hash mismatch"));
            }
        }
        fs::create_dir_all(root.join("pending"))?;
        Ok(Self {
            inner: Arc::new(Inner {
                root: root.into(),
                manifest,
                token_hash: sha256(token.as_bytes()),
                serial: Mutex::new((Instant::now(), 0, 0)),
            }),
        })
    }
    fn audit(&self, event: &str, status: u16) -> io::Result<()> {
        // No authorization value or input text in audit logs.
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.inner.root.join("audit.jsonl"))?;
        writeln!(
            file,
            "{}",
            serde_json::json!({"at":now(),"event":event,"status":status})
        )?;
        file.sync_data()
    }
}
pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/api/v1/manifest", get(manifest))
        .route("/api/v1/dictionaries", get(dictionaries))
        .route("/api/v1/updates", get(updates))
        .route("/api/v1/releases", get(dictionaries))
        .route("/api/v1/artifact", get(artifact))
        .route("/api/v1/delta", get(delta))
        .route("/api/v1/words/submit", post(submit))
        .layer(DefaultBodyLimit::max(2048))
        .with_state(state)
}
async fn manifest(State(state): State<ApiState>) -> Json<SignedManifest> {
    Json(state.inner.manifest.clone())
}
async fn dictionaries(State(state): State<ApiState>) -> Json<serde_json::Value> {
    Json(
        serde_json::json!({"version":state.inner.manifest.manifest.dictionary_version,"sequence":state.inner.manifest.manifest.version,"download":"/api/v1/artifact","format":"nud-v1"}),
    )
}
#[derive(Deserialize)]
struct UpdateQuery {
    from: Option<String>,
}
async fn updates(
    State(state): State<ApiState>,
    Query(query): Query<UpdateQuery>,
) -> Json<serde_json::Value> {
    let manifest = &state.inner.manifest.manifest;
    let unchanged = query.from.as_ref() == Some(&manifest.sha256);
    let differential = manifest
        .delta
        .as_ref()
        .is_some_and(|d| query.from.as_ref() == Some(&d.base_sha256));
    Json(
        serde_json::json!({"available":!unchanged,"kind":if differential{"delta"}else{"full"},"download":if differential{"/api/v1/delta"}else{"/api/v1/artifact"},"manifest":"/api/v1/manifest"}),
    )
}
async fn serve_file(path: PathBuf) -> Result<Response, StatusCode> {
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let size = file
        .metadata()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .len();
    let mut response = Body::from_stream(ReaderStream::new(file)).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/octet-stream"),
    );
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, size.into());
    Ok(response)
}
async fn artifact(State(state): State<ApiState>) -> Result<Response, StatusCode> {
    serve_file(state.inner.root.join("base.nud")).await
}
async fn delta(State(state): State<ApiState>) -> Result<Response, StatusCode> {
    if state.inner.manifest.manifest.delta.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }
    serve_file(state.inner.root.join("delta.json")).await
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Word {
    pub reading: String,
    pub surface: String,
    pub language: String,
    pub source_url: String,
    pub license: String,
    pub share_consent: bool,
}
impl Word {
    pub fn valid(&self) -> bool {
        let field = |s: &str, max: usize| {
            !s.is_empty() && s.chars().count() <= max && !s.chars().any(char::is_control)
        };
        self.share_consent
            && field(&self.reading, 64)
            && field(&self.surface, 64)
            && field(&self.language, 16)
            && field(&self.license, 80)
            && self
                .language
                .bytes()
                .all(|c| c.is_ascii_alphabetic() || c == b'-')
            && self.source_url.starts_with("https://")
            && field(&self.source_url, 512)
            && !self.source_url.contains('@')
            && !self.surface.contains('@')
            && !self.reading.contains('@')
            && self.surface.chars().filter(|c| c.is_ascii_digit()).count() < 7
    }
}
async fn submit(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(word): Json<Word>,
) -> Result<(StatusCode, Json<serde_json::Value>), StatusCode> {
    let supplied = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");
    let digest = sha256(supplied.as_bytes());
    let equal = digest
        .bytes()
        .zip(state.inner.token_hash.bytes())
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0;
    if !equal {
        state
            .audit("word-submit", 401)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        return Err(StatusCode::UNAUTHORIZED);
    }
    if !word.valid() {
        state
            .audit("word-submit", 400)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut serial = state
        .inner
        .serial
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if serial.0.elapsed().as_secs() >= 60 {
        serial.0 = Instant::now();
        serial.1 = 0;
    }
    if serial.1 >= 5 {
        state
            .audit("word-submit", 429)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    serial.1 += 1;
    serial.2 += 1;
    let id = format!("{}-{}", now(), serial.2);
    // Hash-named immutable spool files provide dedup across restarts; never publish automatically.
    let encoded = serde_json::to_vec(&word).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let identity = sha256(&encoded);
    let path = state
        .inner
        .root
        .join("pending")
        .join(format!("{identity}.json"));
    let mut file = match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            return Ok((
                StatusCode::OK,
                Json(serde_json::json!({"status":"already-pending","sha256":identity})),
            ));
        }
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };
    file.write_all(&encoded)
        .and_then(|_| file.sync_all())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    state
        .audit("word-submit", 202)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({"id":id,"status":"pending-human-review","sha256":identity})),
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    const TOKEN: &str = "test-token-32-bytes-long-for-test-only";
    fn state() -> (tempfile::TempDir, ApiState) {
        let dir = tempfile::tempdir().unwrap();
        let dictionary = nextime_core::Dictionary::from_tsv("し\t詩\tnoun\t10\n").unwrap();
        nexc_max::build_dictionary(dir.path().join("base.nud"), &dictionary, 1).unwrap();
        let key = nextime_security::generate_key();
        let manifest = nextime_security::Manifest {
            format: 1,
            version: 1,
            dictionary_version: "test".into(),
            issued_at: now() - 1,
            expires_at: now() + 3600,
            bytes: fs::metadata(dir.path().join("base.nud")).unwrap().len(),
            sha256: file_sha256(dir.path().join("base.nud")).unwrap(),
            delta: None,
        };
        let signed = SignedManifest::sign(manifest, &key).unwrap();
        fs::write(
            dir.path().join("manifest.json"),
            serde_json::to_vec(&signed).unwrap(),
        )
        .unwrap();
        let state = ApiState::new(dir.path(), key.verifying_key(), TOKEN).unwrap();
        (dir, state)
    }
    fn word(consent: bool) -> Word {
        Word {
            reading: "し".into(),
            surface: "詩".into(),
            language: "ja".into(),
            source_url: "https://example.org/public".into(),
            license: "AGPL-3.0-only".into(),
            share_consent: consent,
        }
    }
    async fn send(app: Router, word: Word, token: &str) -> Response {
        app.oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/words/submit")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&word).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
    }
    #[tokio::test]
    async fn public_manifest_and_streamed_artifact() {
        let (dir, state) = state();
        let app = router(state.clone());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/manifest")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let parsed: SignedManifest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.manifest.version, 1);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/artifact")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .as_ref(),
            fs::read(dir.path().join("base.nud")).unwrap()
        );
    }
    #[tokio::test]
    async fn consent_auth_validation_dedup_and_private_audit() {
        let (dir, state) = state();
        let app = router(state);
        assert_eq!(send(app.clone(), word(true), "wrong").await.status(), 401);
        assert_eq!(send(app.clone(), word(false), TOKEN).await.status(), 400);
        assert_eq!(send(app.clone(), word(true), TOKEN).await.status(), 202);
        assert_eq!(send(app, word(true), TOKEN).await.status(), 200);
        assert_eq!(fs::read_dir(dir.path().join("pending")).unwrap().count(), 1);
        let audit = fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        assert!(!audit.contains(TOKEN));
        assert!(!audit.contains("詩"));
    }
    #[tokio::test]
    async fn rate_limit_and_body_bounds() {
        let (_dir, state) = state();
        let app = router(state);
        for _ in 0..5 {
            assert!(
                send(app.clone(), word(true), TOKEN)
                    .await
                    .status()
                    .is_success()
            );
        }
        assert_eq!(send(app.clone(), word(true), TOKEN).await.status(), 429);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/words/submit")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("a".repeat(4096)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 413);
    }
    #[test]
    fn basic_personal_data_checks() {
        let mut w = word(true);
        w.surface = "mail@example.org".into();
        assert!(!w.valid());
        w.surface = "09012345678".into();
        assert!(!w.valid());
        w.surface = "詩".into();
        w.source_url = "http://example.org".into();
        assert!(!w.valid());
    }
}
