//! D8 — the shared "shrink Order PDA to a flags-only tombstone" helper,
//! used by the final `settle_out`, `refund`, and (in its allocate-direct
//! form) `settle_in`. Centralized here rather than duplicated per
//! instruction, because R8's account-tag discipline and the lamport
//! bookkeeping are exactly the kind of thing that's easy to get subtly
//! wrong once and right everywhere else.

use pinocchio::{
    sysvars::{rent::Rent, Sysvar},
    AccountView, Resize,
};

use crate::{
    errors::GatewayError,
    state::{OrderLive, OrderTombstone},
};

/// Shrinks a live Order PDA (204 bytes) down to a tombstone (16 bytes),
/// crediting the reclaimed lamports to `reclaim_to`. The caller is
/// responsible for having already verified `reclaim_to` is the correct
/// recipient (D8: `Config.aggregator`) and is writable.
pub fn terminalize_live_order(
    order_ai: &mut AccountView,
    reclaim_to: &mut AccountView,
    is_fulfilled: bool,
    is_refunded: bool,
) -> Result<(), GatewayError> {
    let bump = {
        let d = order_ai.try_borrow().map_err(|_| GatewayError::InvalidAccountTag)?;
        OrderLive::read_from(&d)?.bump
    };

    let tombstone_rent = Rent::get()
        .map_err(|_| GatewayError::MathOverflow)?
        .try_minimum_balance(OrderTombstone::LEN)
        .map_err(|_| GatewayError::MathOverflow)?;
    let current_lamports = order_ai.lamports();
    let reclaim = current_lamports
        .checked_sub(tombstone_rent)
        .ok_or(GatewayError::MathOverflow)?;

    // Resize before writing — the account's true size is `data_len`, so a
    // stale 204-byte buffer with only the first 16 bytes meaningful would
    // be harmless, but shrinking first keeps `write_to`'s own length
    // check (which now expects exactly 16 bytes) meaningful too.
    order_ai.resize(OrderTombstone::LEN).map_err(|_| GatewayError::InvalidAccountTag)?;

    {
        let mut d = order_ai.try_borrow_mut().map_err(|_| GatewayError::InvalidAccountTag)?;
        OrderTombstone::new(bump, is_fulfilled, is_refunded).write_to(&mut d)?;
    }

    order_ai.set_lamports(tombstone_rent);
    let new_reclaim_balance = reclaim_to
        .lamports()
        .checked_add(reclaim)
        .ok_or(GatewayError::MathOverflow)?;
    reclaim_to.set_lamports(new_reclaim_balance);

    Ok(())
}
