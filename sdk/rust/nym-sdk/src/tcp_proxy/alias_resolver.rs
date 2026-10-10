// alias_resolver.rs
//
// Loads a JSON file mapping human-readable aliases (e.g., "mein-blog")
// to full Nym recipient addresses. Used by the HTTP proxy to resolve
// fantasy domain names entered in the browser's address bar.

use anyhow::{Context, Result};
use nym_sphinx_addressing::Recipient;
use std::collections::HashMap;
use std::path::Path;
use tokio::fs;
use tracing::{info, warn};

/// A thread-safe mapping from alias names to Nym recipients.
#[derive(Clone, Debug, Default)]
pub struct AliasMap {
    inner: HashMap<String, Recipient>,
}

impl AliasMap {
    /// Creates an empty alias map.
    pub fn empty() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Loads aliases from a JSON file.
    ///
    /// The file must be a JSON object where keys are alias names and
    /// values are Nym recipient addresses (base58 strings).
    ///
    /// Example:
    /// ```json
    /// {
    ///   "mein-blog": "client_id@gateway_id",
    ///   "mein-wiki": "other_client@other_gateway"
    /// }
    /// ```
    pub async fn load_from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)
            .await
            .with_context(|| format!("Failed to read alias file: {}", path.display()))?;

        let raw: HashMap<String, String> = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse alias file as JSON: {}", path.display()))?;

        let mut inner = HashMap::new();
        for (alias, addr_str) in raw {
            match Recipient::try_from_base58_string(&addr_str) {
                Ok(recipient) => {
                    info!("Loaded alias '{}' -> {}", alias, recipient);
                    inner.insert(alias.to_lowercase(), recipient);
                }
                Err(e) => {
                    warn!(
                        "Skipping alias '{}': invalid Nym address '{}': {}",
                        alias, addr_str, e
                    );
                }
            }
        }

        info!("Loaded {} aliases from {}", inner.len(), path.display());
        Ok(Self { inner })
    }

    /// Resolves an alias to a Nym recipient.
    ///
    /// Returns `Some(recipient)` if the alias exists, `None` otherwise.
    /// The lookup is case-insensitive.
    pub fn resolve(&self, alias: &str) -> Option<Recipient> {
        self.inner.get(&alias.to_lowercase()).copied()
    }

    /// Returns `true` if the map contains no aliases.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the number of loaded aliases.
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}
