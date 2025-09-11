module smart_wallet::member_index {
    use sui::object::{self, UID, id_address};
    use sui::dynamic_field as df;
    use sui::event;

    // A single global object that owns a namespace of dynamic fields:
    //   key = address of a member (as bytes)
    //   value = vector<address> (list of wallet IDs the member belongs to)
    struct Registry has key, store {
        id: UID,
    }

    const REGISTRY_ID: address = @0x1; // Deploy the Registry at a well‑known address

    /// Initialise the registry – call once after publishing the package.
    public entry fun init_registry(ctx: &mut TxContext) {
        let reg = Registry { id: object::new(ctx) };
        move_to<Registry>(ctx, reg);
    }

    /// Helper to fetch (or create) the global registry object.
    fun get_registry(): &mut Registry {
        borrow_global_mut<Registry>(REGISTRY_ID)
    }

    /// Add a wallet reference for a given member address.
    public fun add_wallet_for_member(member: address, wallet_id: address) {
        let reg = get_registry();
        let key = bcs::to_bytes(&member);
        let existing_opt = df::borrow(&reg.id, key);
        let mut list = if (option::is_some(&existing_opt)) {
            option::unwrap(existing_opt)
        } else {
            vector::empty<address>()
        };
        // Avoid duplicate entries
        let mut i = 0;
        let mut already = false;
        while (i < vector::length(&list)) {
            if (*vector::borrow(&list, i) == wallet_id) {
                already = true;
                break;
            };
            i = i + 1;
        };
        if (!already) {
            vector::push_back(&mut list, wallet_id);
            df::add(&mut reg.id, key, bcs::to_bytes(&list));
        };
    }

    /// Remove a wallet reference when a member is removed from that wallet.
    public fun remove_wallet_for_member(member: address, wallet_id: address) {
        let reg = get_registry();
        let key = bcs::to_bytes(&member);
        let existing_opt = df::borrow(&reg.id, key);
        if (!option::is_some(&existing_opt)) {
            return;
        };
        let mut list = option::unwrap(existing_opt);
        let mut new_list = vector::empty<address>();
        let mut i = 0;
        while (i < vector::length(&list)) {
            let w = *vector::borrow(&list, i);
            if (w != wallet_id) {
                vector::push_back(&mut new_list, w);
            };
            i = i + 1;
        };
        df::add(&mut reg.id, key, bcs::to_bytes(&new_list));
    }

    /// Public view to fetch all wallets a member belongs to.
    public fun wallets_of(member: address): vector<address> {
        let reg = get_registry();
        let key = bcs::to_bytes(&member);
        let opt = df::borrow(&reg.id, key);
        if (option::is_some(&opt)) {
            option::unwrap(opt)
        } else {
            vector::empty<address>()
        }
    }
}