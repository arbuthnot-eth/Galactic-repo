module smart_wallet::helpers {
    use sui::object::{self, UID, id_address};
    use sui::vec_map::{self, VecMap};
    use sui::dynamic_field as df;
    use sui::event;
    use sui::coin::{self, Coin};
    use sui::transfer;
    use sui::sui::SUI;
    use multisig::multisig;
    use smart_wallet::wallet::{SmartWallet, Role, Condition, Action};

    // -----------------------------------------------------------------
    // Compute the deterministic multisig identifier for a given member set
    // **and** a specific threshold.  This is a thin wrapper around the
    // pure function in `multisig::multisig`.  Because the function is pure,
    // calling it on‑chain costs no gas.
    // -----------------------------------------------------------------
    public fun compute_multisig_id(
        members: &VecMap<address, Role>,
        threshold: u64,
    ): address {
        // Gather public keys and **weights as u8** (multisig lib expects u8).
        let mut pks: vector<vector<u8>> = vector[];
        let mut wts: vector<u8> = vector[];
        let keys = vec_map::keys(members);
        let mut i = 0;
        while (i < vector::length(&keys)) {
            let member = vector::borrow(&keys, i);
            let role = vec_map::get(members, member);
            // Fetch stored raw pubkey
            let pk_opt = df::borrow(&member, b"pubkey_" ++ bcs::to_bytes(member));
            let pk = option::unwrap(pk_opt);
            vector::push_back(&mut pks, pk);
            // Truncate weight safely – weights >255 are unsupported by the
            // underlying multisig lib; we guard against that at insertion.
            vector::push_back(&mut wts, (role.weight as u8));
            i = i + 1;
        };
        // The original helper expects a u16 threshold.
        let addr = multisig::derive_multisig_address_quiet(pks, wts, threshold as u16);
        addr
    }

    /// Store (or update) the wallet‑wide deterministic multisig identifier.
    /// The identifier is written under the well‑known key `"multisig_id"` so
    /// that indexers and off‑chain services can read it without scanning the
    /// whole object.
    public fun store_multisig_id(wallet: &SmartWallet) {
        // For wallets that still keep a *global* threshold (legacy UI) we
        // read it from a dynamic field; otherwise we use 0.
        let threshold_opt = df::borrow(&wallet.id, b"global_threshold");
        let threshold = option::map_or(threshold_opt, 0u64, |b| bcs::from_bytes<u64>(b));
        let ms_id = compute_multisig_id(&wallet.members, threshold);
        df::add(&mut wallet.id, b"multisig_id", bcs::to_bytes(&ms_id));
    }

    // -----------------------------------------------------------------
    // Minimal condition checker – replace with oracle integration later.
    // -----------------------------------------------------------------
    public fun check_conditions(conds: &vector<Condition>, clock: &Clock): bool {
        // Example: block‑height condition
        let mut i = 0;
        while (i < vector::length(conds)) {
            let c = vector::borrow(conds, i);
            if (c.kind == b"block_height") {
                let target = bcs::from_bytes<u64>(&c.value);
                if (clock::timestamp_ms(clock) < target) {
                    return false;
                };
            };
            i = i + 1;
        };
        true
    }

    // -----------------------------------------------------------------
    // Execute a simple SUI transfer. The wallet holds its own coins in a
    // dynamic‑field namespace; `coin::take` pulls from there.
    // -----------------------------------------------------------------
    public fun execute_transfer(
        wallet: &mut SmartWallet,
        action: &Action,
        ctx: &mut TxContext,
    ) {
        let amount = bcs::from_bytes<u64>(&action.data);
        let coin = coin::take(&mut wallet.id, amount, ctx);
        transfer::public_transfer(coin, action.target);
    }
}