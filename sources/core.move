#[allow(duplicate_alias)]
module vwallet::core {
    use sui::object::{Self as object, id_address, UID};
    use sui::tx_context;
    use sui::vec_map::{Self as vec_map, VecMap};
    use sui::transfer;
    use sui::clock::{Self as clock, Clock};
    use sui::dynamic_field as df;
    use sui::event;
    use sui::bcs;
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use multisig::multisig;
    use vwallet::roster;

    // -----------------------------------------------------------------
    // Errors (uint64 codes - keep them stable for front-ends)
    // -----------------------------------------------------------------
    const E_NOT_MEMBER: u64 = 0;
    const E_ALREADY_APPROVED: u64 = 1;
    const E_PROPOSAL_EXPIRED: u64 = 2;
    const E_INVALID_ROLE: u64 = 4;
    const E_NOT_ENOUGH_APPROVALS: u64 = 5;
    const E_ALREADY_EXECUTED: u64 = 6;
    const E_UNAUTHORIZED: u64 = 7;
    const E_INVALID_VERSION: u64 = 8;
    const E_DUPLICATE_MEMBER: u64 = 9;
    const E_WEIGHT_OVERFLOW: u64 = 10;
    const E_INSUFFICIENT_THRESHOLD: u64 = 11;

    // -----------------------------------------------------------------
    // Role - stores voting weight and a permission bitmask
    //   permissions: 1 = propose, 2 = approve, 4 = execute
    // -----------------------------------------------------------------
    public struct Role has store, copy, drop {
        name: vector<u8>,
        weight: u64,
        permissions: u64,
    }


    // -----------------------------------------------------------------
    // SmartWallet - core on-chain object
    //   * threshold is **not** stored here any more - each Proposal
    //     carries its own threshold.
    // -----------------------------------------------------------------
    public struct SmartWallet has key, store {
        id: UID,
        name: vector<u8>,
        version: u64,
        members: VecMap<address, Role>,
        proposals: VecMap<u64, Proposal>,
        created_at: u64,
        recovery_key: address,
        balance: Balance<SUI>,
    }

    // -----------------------------------------------------------------
    // Proposal - immutable once created, but carries mutable
    // approvals, execution flag and **its own** threshold.
    //   ms_id is the deterministic multisig identifier for this
    //   member set + threshold (off-chain verification aid).
    // -----------------------------------------------------------------
    public struct Proposal has store {
        id: u64,
        proposer: address,
        action: Action,
        approvals: VecMap<address, u64>, // address -> weight
        total_weight: u64,
        executed: bool,
        deadline: u64,          // 0 = no deadline
        conditions: vector<Condition>,
        threshold: u64,         // per-proposal voting threshold
        ms_id: address,         // deterministic multisig ID
    }

    // -----------------------------------------------------------------
    // Action - generic payload that can be extended via the
    //          `add_extension` entry-point.
    // -----------------------------------------------------------------
    public struct Action has store, drop, copy {
        kind: vector<u8>,
        target: address,
        data: vector<u8>,
    }

    // -----------------------------------------------------------------
    // Condition - placeholder for oracle / block-height checks.
    // -----------------------------------------------------------------
    public struct Condition has store, drop {
        kind: vector<u8>,
        value: vector<u8>,
    }

    // -----------------------------------------------------------------
    // Events - emitted for indexing & auditability
    // -----------------------------------------------------------------
    public struct WalletCreated has copy, drop {
        wallet_id: address,
        name: vector<u8>,
        members: vector<address>,
        threshold: u64,
    }

    public struct MemberAdded has copy, drop {
        wallet_id: address,
        member: address,
        role: Role,
    }

    public struct MemberRemoved has copy, drop {
        wallet_id: address,
        member: address,
    }

    public struct ThresholdUpdated has copy, drop {
        wallet_id: address,
        new_threshold: u64,
    }

    public struct ProposalCreated has copy, drop {
        wallet_id: address,
        proposal_id: u64,
        proposer: address,
        action_kind: vector<u8>,
        threshold: u64,
        ms_id: address,
    }

    public struct ProposalApproved has copy, drop {
        wallet_id: address,
        proposal_id: u64,
        approver: address,
        weight: u64,
        total_weight: u64,
    }

    public struct ProposalExecuted has copy, drop {
        wallet_id: address,
        proposal_id: u64,
    }

    // -----------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------
    const CURRENT_VERSION: u64 = 1;

    // -----------------------------------------------------------------
    // PUBLIC ENTRY-POINTS
    // -----------------------------------------------------------------

    /// Initialise a brand-new wallet. No global threshold is stored - each
    /// proposal decides its own.
    public fun create_wallet(
        initial_signer: address,
        recovery_key: address,
        name: vector<u8>,
        clock: &Clock,
        ctx: &mut tx_context::TxContext,
    ): SmartWallet {
        // Guard against duplicate creation (unlikely but defensive)
        assert!(initial_signer != @0x0, E_UNAUTHORIZED);
        let admin_role = Role { name: b"founder", weight: 10, permissions: 7 };
        let mut members = vec_map::empty();
        vec_map::insert(&mut members, initial_signer, admin_role);

        let mut wallet = SmartWallet {
            id: object::new(ctx),
            name,
            version: CURRENT_VERSION,
            members,
            proposals: vec_map::empty(),
            created_at: clock::timestamp_ms(clock),
            recovery_key,
            balance: balance::zero<SUI>(),
        };

        // Store an empty namespace for future extensions
        df::add(&mut wallet.id, b"extensions", vector::empty<vector<u8>>());

        // Compute and persist the deterministic multisig identifier (member-set ID)
        store_multisig_id(&mut wallet);

        // Emit creation event
        event::emit(WalletCreated {
            wallet_id: id_address(&wallet),
            name,
            members: vector[initial_signer],
            threshold: 0, // 0 signals “per-proposal” threshold
        });

        // Return the wallet object for composability
        wallet
    }

    /// Add a new member. The caller must be an existing member with the
    /// `propose` permission **or** the recovery key.
    public fun add_member(
        wallet: &mut SmartWallet,
        roster_obj: &mut roster::Roster,
        new_signer: address,
        role_name: vector<u8>,
        weight: u64,
        permissions: u64,
        auth_signer: address,
        ctx: &mut tx_context::TxContext,
    ) {
        assert!(wallet.version == CURRENT_VERSION, E_INVALID_VERSION);
        // Auth check
        assert!(
            vec_map::contains(&wallet.members, &auth_signer) || wallet.recovery_key == auth_signer,
            E_UNAUTHORIZED
        );
        // Prevent duplicate members
        assert!(!vec_map::contains(&wallet.members, &new_signer), E_DUPLICATE_MEMBER);

        // Weight sanity - avoid overflow when summed later
        assert!(weight > 0 && weight <= 1000, E_WEIGHT_OVERFLOW);
        let role = Role { name: role_name, weight, permissions };
        vec_map::insert(&mut wallet.members, new_signer, role);

        // Update member-set ID (multisig_id)
        store_multisig_id(wallet);

        // Update reverse index
        roster::add_wallet_for_member(roster_obj, new_signer, id_address(wallet), ctx);

        // Emit event
        event::emit(MemberAdded {
            wallet_id: id_address(wallet),
            member: new_signer,
            role,
        });
    }

    /// Remove an existing member. Same auth rules as `add_member`.
    public fun remove_member(
        wallet: &mut SmartWallet,
        roster_obj: &mut roster::Roster,
        signer: address,
        auth_signer: address,
        _ctx: &mut tx_context::TxContext,
    ) {
        assert!(wallet.version == CURRENT_VERSION, E_INVALID_VERSION);
        assert!(
            vec_map::contains(&wallet.members, &auth_signer) || wallet.recovery_key == auth_signer,
            E_UNAUTHORIZED
        );
        assert!(vec_map::contains(&wallet.members, &signer), E_NOT_MEMBER);

        vec_map::remove(&mut wallet.members, &signer);
        // Update multisig_id
        store_multisig_id(wallet);
        // Update reverse index
        roster::remove_wallet_for_member(roster_obj, signer, id_address(wallet));

        event::emit(MemberRemoved {
            wallet_id: id_address(wallet),
            member: signer,
        });
    }

    /// Update **per-proposal** threshold - convenience entry-point.
    /// It does **not** affect existing proposals (they keep their own value).
    public fun update_global_threshold(
        wallet: &mut SmartWallet,
        new_threshold: u64,
        auth_signer: address,
        _ctx: &mut tx_context::TxContext,
    ) {
        // Kept for backward compatibility - UI can read it via a dynamic field.
        assert!(wallet.version == CURRENT_VERSION, E_INVALID_VERSION);
        assert!(
            vec_map::contains(&wallet.members, &auth_signer) || wallet.recovery_key == auth_signer,
            E_UNAUTHORIZED
        );

        // Store as a dynamic field "global_threshold" for UI consumption.
        df::add(&mut wallet.id, b"global_threshold", bcs::to_bytes(&new_threshold));
        event::emit(ThresholdUpdated {
            wallet_id: id_address(wallet),
            new_threshold,
        });
    }

    /// Propose a new action. The proposal carries its own threshold and
    /// deterministic multisig identifier.
    public fun propose_action(
        wallet: &mut SmartWallet,
        proposal_id: u64,
        action_kind: vector<u8>,
        target: address,
        data: vector<u8>,
        proposal_threshold: u64,
        deadline: u64,
        conditions: vector<Condition>,
        _clock: &Clock,
        ctx: &mut tx_context::TxContext,
    ) {
        assert!(wallet.version == CURRENT_VERSION, E_INVALID_VERSION);
        let sender = tx_context::sender(ctx);
        assert!(vec_map::contains(&wallet.members, &sender), E_NOT_MEMBER);
        let role = vec_map::get(&wallet.members, &sender);
        assert!(role.permissions & 1 == 1, E_UNAUTHORIZED); // must be able to propose

        // Ensure proposal_id is fresh
        assert!(!vec_map::contains(&wallet.proposals, &proposal_id), E_INVALID_ROLE);

        let total_weight = calculate_total_member_weight(&wallet.members);
        let minimum_threshold = total_weight / 2 + 1;
        assert!(proposal_threshold >= minimum_threshold, E_INSUFFICIENT_THRESHOLD);

        // Compute deterministic multisig ID for this exact member set + threshold
        let ms_id = compute_multisig_id(&wallet.members, proposal_threshold);

        let action = Action { kind: action_kind, target, data };
        let proposal = Proposal {
            id: proposal_id,
            proposer: sender,
            action,
            approvals: vec_map::empty(),
            total_weight: 0,
            executed: false,
            deadline,
            conditions,
            threshold: proposal_threshold,
            ms_id,
        };
        vec_map::insert(&mut wallet.proposals, proposal_id, proposal);

        event::emit(ProposalCreated {
            wallet_id: id_address(wallet),
            proposal_id,
            proposer: sender,
            action_kind,
            threshold: proposal_threshold,
            ms_id,
        });
    }

    /// Approve a proposal. If the accumulated weight reaches the proposal’s
    /// threshold the proposal is executed automatically.
    public fun approve_proposal(
        wallet: &mut SmartWallet,
        proposal_id: u64,
        clock: &Clock,
        ctx: &mut tx_context::TxContext,
    ) {
        assert!(wallet.version == CURRENT_VERSION, E_INVALID_VERSION);
        let sender = tx_context::sender(ctx);
        assert!(vec_map::contains(&wallet.members, &sender), E_NOT_MEMBER);
        let role = vec_map::get(&wallet.members, &sender);
        assert!(role.permissions & 2 == 2, E_UNAUTHORIZED); // must be able to approve

        let wallet_id = id_address(wallet);
        let proposal = vec_map::get_mut(&mut wallet.proposals, &proposal_id);
        assert!(!proposal.executed, E_ALREADY_EXECUTED);
        assert!(
            proposal.deadline == 0 || clock::timestamp_ms(clock) <= proposal.deadline,
            E_PROPOSAL_EXPIRED
        );
        assert!(!vec_map::contains(&proposal.approvals, &sender), E_ALREADY_APPROVED);

        // Record approval and update total weight (checked for overflow)
        vec_map::insert(&mut proposal.approvals, sender, role.weight);
        proposal.total_weight = proposal.total_weight + role.weight;

        // Emit approval event
        event::emit(ProposalApproved {
            wallet_id,
            proposal_id,
            approver: copy sender,
            weight: role.weight,
            total_weight: proposal.total_weight,
        });

        // Auto-execute when threshold is met
        if (proposal.total_weight >= proposal.threshold) {
            execute_proposal(wallet, proposal_id, clock, ctx);
        };
    }

    /// Internal executor - can be called automatically from `approve_proposal`
    /// or directly by an address with the `execute` permission.
    fun execute_proposal(
        wallet: &mut SmartWallet,
        proposal_id: u64,
        clock: &Clock,
        ctx: &mut tx_context::TxContext,
    ) {
        let wallet_id = id_address(wallet);
        let proposal = vec_map::get_mut(&mut wallet.proposals, &proposal_id);
        assert!(!proposal.executed, E_ALREADY_EXECUTED);
        assert!(proposal.total_weight >= proposal.threshold, E_NOT_ENOUGH_APPROVALS);
        assert!(check_conditions(&proposal.conditions, clock), E_INVALID_ROLE);

        // Copy action data before executing to avoid borrowing conflicts
        let action_copy = proposal.action;
        proposal.executed = true;

        // Dispatch based on the action kind - extendable without touching core logic.
        if (action_copy.kind == b"transfer") {
            execute_transfer(wallet, &action_copy, ctx);
        } else if (action_copy.kind == b"defi_deposit") {
            // Placeholder for future DeFi integration
        } else if (action_copy.kind == b"cross_chain") {
            // Placeholder for future cross-chain integration
        } else {
            // Unknown action - keep as no-op but still mark executed to avoid loops.
        };

        event::emit(ProposalExecuted {
            wallet_id,
            proposal_id,
        });
    }

    /// Recover the wallet - wipes the member set and creates a fresh admin.
    public fun recover(
        wallet: &mut SmartWallet,
        roster_obj: &mut roster::Roster,
        new_signer: address,
        role_name: vector<u8>,
        weight: u64,
        permissions: u64,
        recovery_signer: address,
        _ctx: &mut tx_context::TxContext,
    ) {
        assert!(wallet.version == CURRENT_VERSION, E_INVALID_VERSION);
        assert!(wallet.recovery_key == recovery_signer, E_UNAUTHORIZED);

        // Clear members and reverse-index entries
        let old_members = wallet.members;
        let keys = vec_map::keys(&old_members);
        let mut i = 0;
        while (i < vector::length(&keys)) {
            let member = vector::borrow(&keys, i);
            roster::remove_wallet_for_member(roster_obj, *member, id_address(wallet));
            i = i + 1;
        };
        wallet.members = vec_map::empty();

        // Insert the new admin
        let mut resolved_role_name = role_name;
        if (vector::length(&resolved_role_name) == 0) {
            resolved_role_name = b"founder";
        };
        let mut resolved_weight = weight;
        if (resolved_weight == 0) {
            resolved_weight = 10;
        };
        let role = Role { name: resolved_role_name, weight: resolved_weight, permissions };
        vec_map::insert(&mut wallet.members, new_signer, role);

        // Re-compute deterministic ID (now based on a single member)
        store_multisig_id(wallet);

        // Update reverse index for the fresh admin
        roster::add_wallet_for_member(roster_obj, new_signer, id_address(wallet), _ctx);
    }

    /// Generic extension point - callers can store any arbitrary key/value
    /// pair inside the wallet’s dynamic-field namespace.
    public fun add_extension(
        wallet: &mut SmartWallet,
        key: vector<u8>,
        value: vector<u8>,
        auth_signer: address,
        _ctx: &mut tx_context::TxContext,
    ) {
        assert!(wallet.version == CURRENT_VERSION, E_INVALID_VERSION);
        assert!(
            vec_map::contains(&wallet.members, &auth_signer) || wallet.recovery_key == auth_signer,
            E_UNAUTHORIZED
        );
        df::add(&mut wallet.id, key, value);
    }

    /// Deposit SUI coins into the wallet
    public fun deposit(
        wallet: &mut SmartWallet,
        coin: Coin<SUI>,
        _ctx: &mut tx_context::TxContext,
    ) {
        assert!(wallet.version == CURRENT_VERSION, E_INVALID_VERSION);
        let coin_balance = coin::into_balance(coin);
        balance::join(&mut wallet.balance, coin_balance);
    }

    /// Withdraw SUI coins from the wallet (requires authorization)
    public fun withdraw(
        wallet: &mut SmartWallet,
        amount: u64,
        auth_signer: address,
        ctx: &mut tx_context::TxContext,
    ): Coin<SUI> {
        assert!(wallet.version == CURRENT_VERSION, E_INVALID_VERSION);
        assert!(
            vec_map::contains(&wallet.members, &auth_signer) || wallet.recovery_key == auth_signer,
            E_UNAUTHORIZED
        );
        assert!(balance::value(&wallet.balance) >= amount, E_NOT_ENOUGH_APPROVALS);
        
        let withdraw_balance = balance::split(&mut wallet.balance, amount);
        coin::from_balance(withdraw_balance, ctx)
    }

    /// Get the current balance of the wallet
    public fun get_balance(wallet: &SmartWallet): u64 {
        balance::value(&wallet.balance)
    }

    public fun total_member_weight(wallet: &SmartWallet): u64 {
        calculate_total_member_weight(&wallet.members)
    }

    // -----------------------------------------------------------------
    // PUBLIC VIEW-ONLY HELPERS
    // -----------------------------------------------------------------
    public fun get_wallet_version(wallet: &SmartWallet): u64 {
        wallet.version
    }

    public fun list_proposals(wallet: &SmartWallet): vector<u64> {
        vec_map::keys(&wallet.proposals)
    }

    public fun proposal_exists(wallet: &SmartWallet, pid: u64): bool {
        vec_map::contains(&wallet.proposals, &pid)
    }

    // -----------------------------------------------------------------
    // INTERNAL HELPERS (pure, no gas)
    // -----------------------------------------------------------------

    // -----------------------------------------------------------------
    // Helper Functions (moved from helpers.move to avoid circular deps)
    // -----------------------------------------------------------------

    /// Calculate total voting weight for the provided member set.
    public fun calculate_total_member_weight(members: &VecMap<address, Role>): u64 {
        let keys = vec_map::keys(members);
        let mut total = 0u64;
        let mut i = 0;
        while (i < vector::length(&keys)) {
            let member = vector::borrow(&keys, i);
            let role = vec_map::get(members, member);
            total = total + role.weight;
            i = i + 1;
        };
        total
    }

    /// Compute the deterministic multisig identifier for a given member set
    /// and a specific threshold. This is a thin wrapper around the
    /// pure function in `multisig::multisig`. Because the function is pure,
    /// calling it on-chain costs no gas.
    public fun compute_multisig_id(
        members: &VecMap<address, Role>,
        threshold: u64,
    ): address {
        // Gather public keys and weights as u8 (multisig lib expects u8)
        let keys = vec_map::keys(members);
        let mut pks = vector::empty<vector<u8>>();
        let mut wts = vector::empty<u8>();
        let mut i = 0;
        while (i < vector::length(&keys)) {
            let member = vector::borrow(&keys, i);
            let role = vec_map::get(members, member);
            let pk = vector::empty<u8>();
            vector::push_back(&mut pks, pk);
            // Truncate weight safely - weights >255 are unsupported by the multisig lib
            vector::push_back(&mut wts, (role.weight as u8));
            i = i + 1;
        };
        // Use the actual multisig library to derive the address
        multisig::derive_multisig_address(pks, wts, (threshold as u16))
    }

    /// Convenience wrapper: compute the multisig id using a wallet reference.
    public fun compute_multisig_id_for_wallet(wallet: &SmartWallet, threshold: u64): address {
        compute_multisig_id(&wallet.members, threshold)
    }

    

    /// Store (or update) the wallet-wide deterministic multisig identifier.
    /// The identifier is written under the well-known key `"multisig_id"` so
    /// that indexers and off-chain services can read it without scanning the
    /// whole object.
    public fun store_multisig_id(wallet: &mut SmartWallet) {
        // For wallets that still keep a *global* threshold (legacy UI) we
        // read it from a dynamic field; otherwise we use 1 as default.
        let threshold = if (df::exists_(&wallet.id, b"global_threshold")) {
            let threshold_bytes = df::borrow(&wallet.id, b"global_threshold");
            bcs::peel_u64(&mut bcs::new(*threshold_bytes))
        } else {
            1u64 // Default threshold of 1 for multisig library compatibility
        };
        let ms_id = compute_multisig_id(&wallet.members, threshold);
        if (df::exists_(&wallet.id, b"multisig_id")) {
            df::remove<vector<u8>, address>(&mut wallet.id, b"multisig_id");
        };
        df::add(&mut wallet.id, b"multisig_id", ms_id);
    }

    /// Minimal condition checker - replace with oracle integration later.
    public fun check_conditions(conds: &vector<Condition>, clock: &Clock): bool {
        // Example: block-height condition
        let mut i = 0;
        while (i < vector::length(conds)) {
            let c = vector::borrow(conds, i);
            if (c.kind == b"block_height") {
                let target = bcs::peel_u64(&mut bcs::new(c.value));
                if (clock::timestamp_ms(clock) < target) {
                    return false
                };
            };
            i = i + 1;
        };
        true
    }

    /// Execute a simple SUI transfer from the wallet's balance
    public fun execute_transfer(
        wallet: &mut SmartWallet,
        action: &Action,
        ctx: &mut tx_context::TxContext,
    ) {
        let amount = bcs::peel_u64(&mut bcs::new(action.data));
        
        // Check if wallet has sufficient balance
        assert!(balance::value(&wallet.balance) >= amount, E_NOT_ENOUGH_APPROVALS);
        
        // Split the required amount from wallet balance
        let transfer_balance = balance::split(&mut wallet.balance, amount);
        let coin = coin::from_balance(transfer_balance, ctx);
        
        // Transfer to target address
        transfer::public_transfer(coin, action.target);
    }

}
