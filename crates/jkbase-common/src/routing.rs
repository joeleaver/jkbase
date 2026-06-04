//! Shared routing types used by both the proxy (reader) and the control plane
//! (writer) so the in-memory domain map they share is the same concrete type.

use serde::{Deserialize, Serialize};

/// Resolution target for a claimed host: which project owns it (so the proxy can
/// wake the right VM even while hibernated) and which site within that project
/// the host serves (`None` = the default site).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainTarget {
    pub project_id: String,
    pub site: Option<String>,
}
