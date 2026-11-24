//! Optional on-device prompt-injection classifier (cargo feature `ml`).
//!
//! Runs ProtectAI's `deberta-v3-base-prompt-injection-v2` (Apache-2.0) with
//! ONNX Runtime on top of the heuristic inspectors, which keep working
//! without it. The model and tokenizer are downloaded on first use from a
//! pinned Hugging Face revision and verified against pinned SHA-256 digests
//! before they are used; a mismatch aborts loading.
//!
//! ONNX Runtime is loaded dynamically (`onnxruntime.dll`): set
//! `ORT_DYLIB_PATH` to the DLL from an ONNX Runtime release (CPU, DirectML
//! for GPU/NPU) or let Rousseau find one on the `PATH`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ort::session::Session;
use ort::session::builder::GraphOptimizationLevel;
use ort::value::TensorRef;
use rousseau_core::event::{FindingInfo, Severity};
use sha2::{Digest, Sha256};
use tokenizers::Tokenizer;

use super::finding;

/// Hugging Face revision the files are pinned to.
pub const REVISION: &str = "90c9989b1a342275dd0d1a95aad283c04e075671";
const BASE: &str = "https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/resolve";
/// `onnx/model.onnx` (738,563,188 bytes).
pub const MODEL_SHA256: &str = "f0ea7f239f765aedbde7c9e163a7cb38a79c5b8853d3f76db5152172047b228c";
/// `onnx/tokenizer.json` (8,648,886 bytes).
pub const TOKENIZER_SHA256: &str = "752fe5f0d5678ad563e1bd2ecc1ddf7a3ba7e2024d0ac1dba1a72975e26dff2f";
/// Maximum sequence length of the model.
const MAX_TOKENS: usize = 512;

/// Classifier errors.
#[derive(Debug, thiserror::Error)]
pub enum ClassifierError {
    #[error("download failed: {0}")]
    Download(String),
    #[error("{file}: SHA-256 mismatch (expected {expected}, got {actual}); refusing to load")]
    Digest { file: String, expected: String, actual: String },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("tokenizer: {0}")]
    Tokenizer(String),
    #[error("ONNX Runtime: {0}")]
    Runtime(String),
}

fn sha256_file(path: &Path) -> Result<String, ClassifierError> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(rousseau_core::hash::hex(&h.finalize()))
}

async fn fetch(url: &str, dest: &Path, sha: &str) -> Result<(), ClassifierError> {
    if dest.is_file() && sha256_file(dest)? == sha {
        return Ok(());
    }
    crate::install_crypto_provider();
    let client = reqwest::Client::new();
    let mut resp = client.get(url).send().await.map_err(|e| ClassifierError::Download(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(ClassifierError::Download(format!("{url}: HTTP {}", resp.status())));
    }
    let tmp = dest.with_extension("part");
    let mut out = std::fs::File::create(&tmp)?;
    let mut h = Sha256::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| ClassifierError::Download(e.to_string()))? {
        h.update(&chunk);
        out.write_all(&chunk)?;
    }
    out.flush()?;
    drop(out);
    let actual = rousseau_core::hash::hex(&h.finalize());
    if actual != sha {
        let _ = std::fs::remove_file(&tmp);
        return Err(ClassifierError::Digest { file: url.into(), expected: sha.into(), actual });
    }
    std::fs::rename(&tmp, dest)?;
    Ok(())
}

/// Downloads (if needed) and verifies the model files into `dir`.
pub async fn ensure_model(dir: &Path) -> Result<(PathBuf, PathBuf), ClassifierError> {
    std::fs::create_dir_all(dir)?;
    let model = dir.join("prompt-injection-v2.onnx");
    let tokenizer = dir.join("prompt-injection-v2.tokenizer.json");
    fetch(&format!("{BASE}/{REVISION}/onnx/tokenizer.json"), &tokenizer, TOKENIZER_SHA256).await?;
    fetch(&format!("{BASE}/{REVISION}/onnx/model.onnx"), &model, MODEL_SHA256).await?;
    Ok((model, tokenizer))
}

/// A loaded classifier.
pub struct Classifier {
    /// Keeps the ONNX Runtime environment alive for the session.
    _env: ort::environment::Environment,
    session: Mutex<Session>,
    tokenizer: Tokenizer,
    threshold: f32,
}

impl Classifier {
    /// Loads verified files. `threshold` is the INJECTION probability above
    /// which a finding is raised (0.9 is a sensible default).
    pub fn load(model: &Path, tokenizer: &Path, threshold: f32) -> Result<Self, ClassifierError> {
        for (path, sha) in [(model, MODEL_SHA256), (tokenizer, TOKENIZER_SHA256)] {
            let actual = sha256_file(path)?;
            if actual != sha {
                return Err(ClassifierError::Digest { file: path.display().to_string(), expected: sha.into(), actual });
            }
        }
        let rt = |e: &dyn std::fmt::Display| ClassifierError::Runtime(e.to_string());
        let builder = match std::env::var("ORT_DYLIB_PATH") {
            Ok(dll) => ort::init_from(dll).map_err(|e| rt(&e))?,
            Err(_) => ort::init(),
        };
        let env = builder.with_name("rousseau").build().map_err(|e| rt(&e))?;
        let session = Session::builder(&env)
            .map_err(|e| rt(&e))?
            .with_optimization_level(GraphOptimizationLevel::Level3)
            .map_err(|e| rt(&e))?
            .commit_from_file(model)
            .map_err(|e| rt(&e))?;
        let tokenizer = Tokenizer::from_file(tokenizer).map_err(|e| ClassifierError::Tokenizer(e.to_string()))?;
        Ok(Self { _env: env, session: Mutex::new(session), tokenizer, threshold })
    }

    /// Probability (0–1) that `text` is a prompt injection.
    pub fn score(&self, text: &str) -> Result<f32, ClassifierError> {
        let enc = self.tokenizer.encode(text, true).map_err(|e| ClassifierError::Tokenizer(e.to_string()))?;
        let n = enc.get_ids().len().min(MAX_TOKENS);
        let ids: Vec<i64> = enc.get_ids()[..n].iter().map(|&x| i64::from(x)).collect();
        let mask: Vec<i64> = enc.get_attention_mask()[..n].iter().map(|&x| i64::from(x)).collect();
        let shape = [1usize, n];
        let mut session = self.session.lock().map_err(|_| ClassifierError::Runtime("session lock poisoned".into()))?;
        let outputs = session
            .run(ort::inputs![
                "input_ids" => TensorRef::from_array_view((shape, ids.as_slice())).map_err(|e| ClassifierError::Runtime(e.to_string()))?,
                "attention_mask" => TensorRef::from_array_view((shape, mask.as_slice())).map_err(|e| ClassifierError::Runtime(e.to_string()))?,
            ])
            .map_err(|e| ClassifierError::Runtime(e.to_string()))?;
        let (_, logits) = outputs[0].try_extract_tensor::<f32>().map_err(|e| ClassifierError::Runtime(e.to_string()))?;
        if logits.len() < 2 {
            return Err(ClassifierError::Runtime("unexpected logits shape".into()));
        }
        // Labels: 0 = SAFE, 1 = INJECTION. Softmax over the two logits.
        let (safe, inj) = (logits[0], logits[1]);
        let m = safe.max(inj);
        let (es, ei) = ((safe - m).exp(), (inj - m).exp());
        Ok(ei / (es + ei))
    }

    /// A finding if `text` scores above the threshold.
    pub fn inspect(&self, text: &str) -> Option<FindingInfo> {
        if text.trim().len() < 20 {
            return None;
        }
        match self.score(text) {
            Ok(p) if p >= self.threshold => Some(finding(
                "classifier",
                "classifier.prompt_injection",
                if p >= 0.98 { Severity::High } else { Severity::Medium },
                "Possible prompt injection (on-device classifier)",
                format!("deberta-v3-base-prompt-injection-v2 scored {:.1}% injection.", p * 100.0),
            )),
            Ok(_) => None,
            Err(e) => {
                tracing::debug!(error = %e, "classifier failed");
                None
            }
        }
    }
}
