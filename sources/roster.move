#[allow(duplicate_alias)]
module vwallet::roster {
    use sui::object::{Self as object, UID};
    use sui::tx_context;
    use sui::transfer;
    use sui::table::{Self as table, Table};
    use sui::event;

    // Events for indexing and off-chain backfill
    public struct Rostered has copy, drop { member: address, wallet: address }
    public struct Unrostered has copy, drop { member: address, wallet: address }

    // Per-member set of wallets (table + key list for iteration)
    public struct MemberSet has store {
        wallets: Table<address, bool>,
        keys: vector<address>,
    }

    // Global roster object
    public struct Roster has key, store {
        id: UID,
        by_member: Table<address, MemberSet>,
        version: u64,
        keys: vector<address>,
    }

    /// Initialize the roster - call once after publishing the package.
    public fun init_roster(ctx: &mut tx_context::TxContext) {
        let reg = Roster {
            id: object::new(ctx),
            by_member: table::new<address, MemberSet>(ctx),
            version: 1,
            keys: vector::empty<address>(),
        };
        transfer::share_object(reg);
    }

    // Internal: ensure a MemberSet exists for a member; returns a mutable ref
    fun ensure_member_set(roster: &mut Roster, member: address, ctx: &mut tx_context::TxContext): &mut MemberSet {
        if (!table::contains(&roster.by_member, member)) {
            let ms = MemberSet { wallets: table::new<address, bool>(ctx), keys: vector::empty<address>() };
            table::add(&mut roster.by_member, member, ms);
            // Track member key for iteration and cleanup
            vector::push_back(&mut roster.keys, member);
        };
        table::borrow_mut(&mut roster.by_member, member)
    }

    /// Add a wallet reference for a given member address.
    public fun add_wallet_for_member(roster: &mut Roster, member: address, wallet_id: address, ctx: &mut tx_context::TxContext) {
        let ms = ensure_member_set(roster, member, ctx);
        if (!table::contains(&ms.wallets, wallet_id)) {
            table::add(&mut ms.wallets, wallet_id, true);
            vector::push_back(&mut ms.keys, wallet_id);
            event::emit(Rostered { member, wallet: wallet_id });
        };
    }

    /// Remove a wallet reference when a member is removed from that wallet.
    public fun remove_wallet_for_member(roster: &mut Roster, member: address, wallet_id: address) {
        if (!table::contains(&roster.by_member, member)) return;
        let is_empty = {
            let ms = table::borrow_mut(&mut roster.by_member, member);
            if (table::contains(&ms.wallets, wallet_id)) {
                // Remove from table
                table::remove(&mut ms.wallets, wallet_id);
                // Remove from keys vector (linear scan)
                let mut i = 0;
                while (i < vector::length(&ms.keys)) {
                    let w = *vector::borrow(&ms.keys, i);
                    if (w == wallet_id) {
                        vector::swap_remove(&mut ms.keys, i);
                        break
                    };
                    i = i + 1;
                };
                event::emit(Unrostered { member, wallet: wallet_id });
            };
            // Capture emptiness while borrow is active
            vector::length(&ms.keys) == 0
        };
        // After borrow is released, if member set became empty, remove the member entry entirely
        if (is_empty) {
            let ms_val = table::remove(&mut roster.by_member, member);
            // Take wallets field by value and destroy the empty table
            let MemberSet { wallets, keys: _ } = ms_val;
            table::destroy_empty(wallets);
            // Remove member from roster.keys
            let mut j = 0;
            while (j < vector::length(&roster.keys)) {
                let m = *vector::borrow(&roster.keys, j);
                if (m == member) {
                    vector::swap_remove(&mut roster.keys, j);
                    break
                };
                j = j + 1;
            };
        };
    }

    /// Get all wallets a member belongs to (copy of keys)
    public fun wallets_of(roster: &Roster, member: address): vector<address> {
        if (!table::contains(&roster.by_member, member)) return vector::empty<address>();
        let ms_ref = table::borrow(&roster.by_member, member);
        // Return a copy of keys
        let mut out = vector::empty<address>();
        let mut i = 0;
        while (i < vector::length(&ms_ref.keys)) {
            let w = *vector::borrow(&ms_ref.keys, i);
            vector::push_back(&mut out, w);
            i = i + 1;
        };
        out
    }

    // Test-only functions
    #[test_only]
    public fun create_roster_for_testing(ctx: &mut tx_context::TxContext): Roster {
        Roster { id: object::new(ctx), by_member: table::new<address, MemberSet>(ctx), version: 1, keys: vector::empty<address>() }
    }

    #[test_only]
    public fun destroy_roster_for_testing(roster: Roster) {
        // Take ownership of fields so we can clean them up explicitly
        let Roster { id, mut by_member, version: _, keys } = roster;
        // Remove all member sets, ensuring inner tables are empty/destroyed
        let mut i = 0;
        while (i < vector::length(&keys)) {
            let member = *vector::borrow(&keys, i);
            if (table::contains(&by_member, member)) {
                let ms_taken = table::remove(&mut by_member, member);
                // Drain the inner wallets table using the recorded keys, then destroy
                let MemberSet { mut wallets, keys: wkeys } = ms_taken;
                let mut j = 0;
                while (j < vector::length(&wkeys)) {
                    let wid = *vector::borrow(&wkeys, j);
                    if (table::contains(&wallets, wid)) {
                        table::remove(&mut wallets, wid);
                    };
                    j = j + 1;
                };
                table::destroy_empty(wallets);
            };
            i = i + 1;
        };
        // Now the outer table should be empty; destroy it
        table::destroy_empty(by_member);
        // Finally delete the UID
        object::delete(id);
        // keys vector is dropped naturally
    }

}
