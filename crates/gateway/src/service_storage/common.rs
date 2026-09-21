//! Extracted from `service_storage.rs`; re-exported from `crate::service_storage`.

use super::*;

/// Reservation headroom for physical versions a managed generation may accrue
/// across exact-version recovery before its logical commit settles.
pub(crate) const MANAGED_STREAMING_PUT_HEADROOM: u64 = 4;

pub(crate) async fn defer_delete_settlement(
    repository: &Arc<dyn ManagedRepository>,
    operation_id: uuid::Uuid,
    receipt_id: uuid::Uuid,
) {
    if repository
        .defer_delete_settlement(operation_id, receipt_id)
        .await
        .is_err()
    {
        warn!(
            operation_id = %operation_id,
            "managed DELETE settlement retry could not be deferred"
        );
    }
}

pub(crate) const LEGACY_VIRTUAL_NODES: usize = 150;

impl std::fmt::Debug for dyn ManagedRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedRepository")
            .field("durable", &self.is_durable())
            .finish()
    }
}
