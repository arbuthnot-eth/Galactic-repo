#[allow(duplicate_alias)]
module vwallet_core::member_index {
    use sui::object::{Self as object, UID};
    use sui::tx_context;
    use sui::transfer;
    use sui::dynamic_field as df;
    use sui::bcs;

    // A single global object that owns a namespace of dynamic fields:
    //   key = address of a member (as bytes)
    //   value = vector<address> (list of wallet IDs the member belongs to)
    public struct Registry has key, store {
        id: UID,
    }

    /// Initialize the registry - call once after publishing the package.
    public fun init_registry(ctx: &mut tx_context::TxContext) {
        let reg = Registry { id: object::new(ctx) };
        transfer::share_object(reg);
    }

    /// Add a wallet reference for a given member address.
    public fun add_wallet_for_member(registry: &mut Registry, member: address, wallet_id: address) {
        let key = bcs::to_bytes(&member);
        let mut list = if (df::exists_(&registry.id, key)) {
            *df::borrow(&registry.id, key)
        } else {
            vector::empty<address>()
        };
        
        // Avoid duplicate entries
        let mut i = 0;
        let mut already = false;
        while (i < vector::length(&list)) {
            if (*vector::borrow(&list, i) == wallet_id) {
                already = true;
                break
            };
            i = i + 1;
        };
        
        if (!already) {
            vector::push_back(&mut list, wallet_id);
            // Remove existing field if present
            if (df::exists_(&registry.id, key)) {
                df::remove<vector<u8>, vector<address>>(&mut registry.id, key);
            };
            df::add(&mut registry.id, key, list);
        };
    }

    /// Remove a wallet reference when a member is removed from that wallet.
    public fun remove_wallet_for_member(registry: &mut Registry, member: address, wallet_id: address) {
        let key = bcs::to_bytes(&member);
        if (!df::exists_(&registry.id, key)) {
            return
        };
        
        let list = *df::borrow(&registry.id, key);
        let mut new_list = vector::empty<address>();
        let mut i = 0;
        
        while (i < vector::length(&list)) {
            let w = *vector::borrow(&list, i);
            if (w != wallet_id) {
                vector::push_back(&mut new_list, w);
            };
            i = i + 1;
        };
        
        // Update the field
        df::remove<vector<u8>, vector<address>>(&mut registry.id, key);
        if (!vector::is_empty(&new_list)) {
            df::add(&mut registry.id, key, new_list);
        };
    }

    /// Get all wallets a member belongs to
    public fun wallets_of(registry: &Registry, member: address): vector<address> {
        let key = bcs::to_bytes(&member);
        if (df::exists_(&registry.id, key)) {
            *df::borrow(&registry.id, key)
        } else {
            vector::empty<address>()
        }
    }

    // Test-only functions
    #[test_only]
    public fun create_registry_for_testing(ctx: &mut tx_context::TxContext): Registry {
        Registry { id: object::new(ctx) }
    }

    #[test_only]
    public fun destroy_registry_for_testing(registry: Registry) {
        let Registry { id } = registry;
        object::delete(id);
    }

}