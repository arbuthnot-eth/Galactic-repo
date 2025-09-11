module smart_wallet::wallet {
    use sui::object::{self, UID, id_address};
    use sui::tx_context::{self, TxContext};
    use sui::vec_map::{self, VecMap};
    use sui::coin::{self, Coin};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::clock::{self, Clock};
    use sui::dynamic_field as df;
    use sui::event;
    use multisig::multisig;
    use smart_wallet::helpers;
    use smart_wallet::member_index;
    use smart_wallet::utils;

    // ──────────────────────────────────────────────────────────────
    // Errors (uint64 codes – keep them stable for front‑ends)
    // ──────────────────────────────────────────────────────────────
    const E_NOT_MEMBER: u64 = 0;
    const E_ALREADY_APPROVED: u64 = 1;
    const E_PROPOSAL_EXPIRED: u64 = 2;
    const E_INVALID_THRESHOLD: u64 = 3;
    const E_INVALID_ROLE: u64 = 4;
    const E_NOT_ENOUGH_APPROVALS: u64 = 5;
    const E_ALREADY_EXECUTED: u64 = 6;
    const E_UNAUTHORIZED: u64 = 7;
    const E_INVALID_VERSION: u64 = 8;
    const E_DUPLICATE_MEMBER: u64 = 9;
    const E_WEIGHT_OVERFLOW: u64 = 10;

    // ──────────────────────────────────────────────────────────────
    // Role – stores voting weight and a permission bitmask
    //   permissions: 1 = propose, 2 = approve, 4 = execute
    // ──────────────────────────────────────────────────────────────
    struct Role has store, copy, drop {
        name: vector<u8>,
        weight: u64,
        permissions: u64,
    }

    // ──────────────────────────────────────────────────────────────
    // SmartWallet – core on‑chain object
    //   * threshold is **not** stored here any more – each Proposal
    //     carries its own threshold.
    // ──────────────────────────────────────────────────────────────
    struct SmartWallet has key, store {
        id: UID,
        name: vector<u8>,
        version: u64,
        members: VecMap<address, Role>,
        proposals: VecMap<u64, Proposal>,
        created_at: u64,
        recovery_key: address,
    }

    // ──────────────────────────────────────────────────────────────
    // Proposal – immutable once created, but carries mutable
    // approvals, execution flag and **its own** threshold.
    //   ms_id is the deterministic multisig identifier for this
    //   member set + threshold (off‑chain verification aid).
    // ──────────────────────────────────────────────────────────────
    struct Proposal has store {
        id: u64,
        proposer: address,
        action: Action,
        approvals: VecMap<address, u64>, // address → weight
        total_weight: u64,
        executed: bool,
        deadline: u64,          // 0 = no deadline
        conditions: vector<Condition>,
        threshold: u64,         // per‑proposal voting threshold
        ms_id: address,         // deterministic multisig ID
    }

    // ──────────────────────────────────────────────────────────────
    // Action – generic payload that can be extended via the
    //          `add_extension` entry‑point.
    // ──────────────────────────────────────────────────────────────
    struct Action has store, drop {
        kind: vector<u8>,
        target: address,
        data: vector<u8>,
    }

    // ──────────────────────────────────────────────────────────────
    // Condition – placeholder for oracle / block‑height checks.
    // ──────────────────────────────────────────────────────────────
    struct Condition has store, drop {
        kind: vector<u8>,
        value: vector<u8>,
    }

    // ──────────────────────────────────────────────────────────────
    // Events – emitted for indexing & auditability
    // ──────────────────────────────────────────────────────────────
    struct WalletCreated has copy, drop {
        wallet_id: address,
        name: vector<u8>,
        members: vector<address>,
        threshold: u64,
    }

    struct MemberAdded has copy, drop {
        wallet_id: address,
        member: address,
        role: Role,
    }

    struct MemberRemoved has copy, drop {
        wallet_id: address,
        member: address,
    }

    struct ThresholdUpdated has copy, drop {
        wallet_id: address,
        new_threshold: u64,
    }

    struct ProposalCreated has copy, drop {
        wallet_id: address,
        proposal_id: u64,
        proposer: address,
        action_kind: vector<u8>,
        threshold: u64,
        ms_id: address,
    }

    struct ProposalApproved has copy, drop {
        wallet_id: address,
        proposal_id: u64,
        approver: address,
        weight: u64,
        total_weight: u64,
    }

    struct ProposalExecuted has copy, drop {
        wallet_id: address,
        proposal_id: u64,
    }

    // ──────────────────────────────────────────────────────────────
    // Constants
    // ──────────────────────────────────────────────────────────────
    const CURRENT_VERSION: u64 = 1;

    // ──────────────────────────────────────────────────────────────
    // PUBLIC ENTRY‑POINTS
    // ──────────────────────────────────────────────────────────────

    /// Initialise a brand‑new wallet. No global threshold is stored – each
    /// proposal decides its own.
    public entry fun create_wallet(
        initial_signer: address,
        recovery_key: address,
        name: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        // Guard against duplicate creation (unlikely but defensive)
        assert!(initial_signer != @0x0, E_UNAUTHORIZED);
        let admin_role = Role { name: b"admin", weight: 1, permissions: 7 };
        let mut members = vec_map::empty();
        vec_map::insert(&mut members, initial_signer, admin_role);

        let wallet = SmartWallet {
            id: object::new(ctx),
            name,
            version: CURRENT_VERSION,
            members,
            proposals: vec_map::empty(),
            created_at: clock::timestamp_ms(clock),
            recovery_key,
        };

        // Store an empty namespace for future extensions
        df::add(&mut wallet.id, b"extensions", vector::empty<vector<u8>>());

        // Compute and persist the deterministic multisig identifier (member‑set ID)
        helpers::store_multisig_id(&wallet);

        // Emit creation event
        event::emit(WalletCreated {
            wallet_id: id_address(&wallet),
            name,
            members: vector[initial_signer],
            threshold: 0, // 0 signals “per‑proposal” threshold
        });

        // Transfer the newly minted object to the caller
        transfer::transfer(wallet, tx_context::sender(ctx));
    }

    /// Add a new member. The caller must be an existing member with the
    /// `propose` permission **or** the recovery key.
    public entry fun add_member(
        wallet: &mut SmartWallet,
        new_signer: address,
        pubkey: vector<u8>,          // raw public‑key bytes (stored for ID computation)
        role_name: vector<u8>,
        weight: u64,
        permissions: u64,
        auth_signer: address,
        ctx: &mut TxContext,
    ) {
        assert!(wallet.version == CURRENT_VERSION, E_INVALID_VERSION);
        // Auth check
        assert!(
            vec_map::contains(&wallet.members, &auth_signer) || wallet.recovery_key == auth_signer,
            E_UNAUTHORIZED
        );
        // Prevent duplicate members
        assert!(!vec_map::contains(&wallet.members, &new_signer), E_DUPLICATE_MEMBER);

        // Weight sanity – avoid overflow when summed later
        assert!(weight > 0, E_WEIGHT_OVERFLOW);
        let role = Role { name: role_name, weight, permissions };
        vec_map::insert(&mut wallet.members, new_signer, role);
        // Store the raw public key for deterministic ID recomputation
        df::add(&mut wallet.id, b"pubkey_" ++ bcs::to_bytes(&new_signer), pubkey);

        // Update member‑set ID (multisig_id)
        helpers::store_multisig_id(wallet);

        // Update reverse index (optional, cheap)
        member_index::add_wallet_for_member(new_signer, id_address(wallet));

        // Emit event
        event::emit(MemberAdded {
            wallet_id: id_address(wallet),
            member: new_signer,
            role,
        });
    }

    /// Remove an existing member. Same auth rules as `add_member`.
    public entry fun remove_member(
        wallet: &mut SmartWallet,
        signer: address,
        auth_signer: address,
        ctx: &mut TxContext,
    ) {
        assert!(wallet.version == CURRENT_VERSION, E_INVALID_VERSION);
        assert!(
            vec_map::contains(&wallet.members, &auth_signer) || wallet.recovery_key == auth_signer,
            E_UNAUTHORIZED
        );
        assert!(vec_map::contains(&wallet.members, &signer), E_NOT_MEMBER);

        vec_map::remove(&mut wallet.members, &signer);
        // Clean up stored pubkey
        df::remove(&mut wallet.id, b"pubkey_" ++ bcs::to_bytes(&signer));
        // Update multisig_id
        helpers::store_multisig_id(wallet);
        // Update reverse index
        member_index::remove_wallet_for_member(signer, id_address(wallet));

        event::emit(MemberRemoved {
            wallet_id: id_address(wallet),
            member: signer,
        });
    }

    /// Update **per‑proposal** threshold – convenience entry‑point.
    /// It does **not** affect existing proposals (they keep their own value).
    public entry fun update_global_threshold(
        wallet: &mut SmartWallet,
        new_threshold: u64,
        auth_signer: address,
        ctx: &mut TxContext,
    ) {
        // Kept for backward compatibility – UI can read it via a dynamic field.
        assert!(wallet.version == CURRENT_VERSION, E_INVALID_VERSION);
        assert!(
            vec_map::contains(&wallet.members, &auth_signer) || wallet.recovery_key == auth_signer,
            E_UNAUTHORIZED
        );

        // Store as a dynamic field “global_threshold” for UI consumption.
        df::add(&mut wallet.id, b"global_threshold", bcs::to_bytes(&new_threshold));
        event::emit(ThresholdUpdated {
            wallet_id: id_address(wallet),
            new_threshold,
        });
    }

    /// Propose a new action. The proposal carries its own threshold and
    /// deterministic multisig identifier.
    public entry fun propose_action(
        wallet: &mut SmartWallet,
        proposal_id: u64,
        action_kind: vector<u8>,
        target: address,
        data: vector<u8>,
        proposal_threshold: u64,
        deadline: u64,
        conditions: vector<Condition>,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        assert!(wallet.version == CURRENT_VERSION, E_INVALID_VERSION);
        let sender = tx_context::sender(ctx);
        assert!(vec_map::contains(&wallet.members, &sender), E_NOT_MEMBER);
        let role = vec_map::get(&wallet.members, &sender);
        assert!(role.permissions & 1 == 1, E_UNAUTHORIZED); // must be able to propose

        // Ensure proposal_id is fresh
        assert!(!vec_map::contains(&wallet.proposals, &proposal_id), E_INVALID_ROLE);

        // Compute deterministic multisig ID for this exact member set + threshold
        let ms_id = helpers::compute_multisig_id(&wallet.members, proposal_threshold);

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
    public entry fun approve_proposal(
        wallet: &mut SmartWallet,
        proposal_id: u64,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        assert!(wallet.version == CURRENT_VERSION, E_INVALID_VERSION);
        let sender = tx_context::sender(ctx);
        assert!(vec_map::contains(&wallet.members, &sender), E_NOT_MEMBER);
        let role = vec_map::get(&wallet.members, &sender);
        assert!(role.permissions & 2 == 2, E_UNAUTHORIZED); // must be able to approve

        let proposal = vec_map::get_mut(&mut wallet.proposals, &proposal_id);
        assert!(!proposal.executed, E_ALREADY_EXECUTED);
        assert!(
            proposal.deadline == 0 || clock::timestamp_ms(clock) <= proposal.deadline,
            E_PROPOSAL_EXPIRED
        );
        assert!(!vec_map::contains(&proposal.approvals, &sender), E_ALREADY_APPROVED);

        // Record approval and update total weight (checked for overflow)
        vec_map::insert(&mut proposal.approvals, sender, role.weight);
        proposal.total_weight = utils::safe_add_u64(proposal.total_weight, role.weight);

        // Emit approval event
        event::emit(ProposalApproved {
            wallet_id: id_address(wallet),
            proposal_id,
            approver: sender,
            weight: role.weight,
            total_weight: proposal.total_weight,
        });

        // Auto‑execute when threshold is met
        if (proposal.total_weight >= proposal.threshold) {
            execute_proposal(wallet, proposal_id, clock, ctx);
        };
    }

    /// Internal executor – can be called automatically from `approve_proposal`
    /// or directly by an address with the `execute` permission.
    fun execute_proposal(
        wallet: &mut SmartWallet,
        proposal_id: u64,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        let proposal = vec_map::get_mut(&mut wallet.proposals, &proposal_id);
        assert!(!proposal.executed, E_ALREADY_EXECUTED);
        assert!(proposal.total_weight >= proposal.threshold, E_NOT_ENOUGH_APPROVALS);
        assert!(helpers::check_conditions(&proposal.conditions, clock), E_INVALID_ROLE);

        // Dispatch based on the action kind – extendable without touching core logic.
        if (proposal.action.kind == b"transfer") {
            helpers::execute_transfer(wallet, &proposal.action, ctx);
        } else if (proposal.action.kind == b"defi_deposit") {
            // Placeholder for future DeFi integration
        } else if (proposal.action.kind == b"cross_chain") {
            // Placeholder for future cross‑chain integration
        } else {
            // Unknown action – keep as no‑op but still mark executed to avoid loops.
        };

        proposal.executed = true;
        event::emit(ProposalExecuted {
            wallet_id: id_address(wallet),
            proposal_id,
        });
    }

    /// Recover the wallet – wipes the member set and creates a fresh admin.
    public entry fun recover(
        wallet: &mut SmartWallet,
        new_signer: address,
        pubkey: vector<u8>,
        role_name: vector<u8>,
        weight: u64,
        permissions: u64,
        recovery_signer: address,
        ctx: &mut TxContext,
    ) {
        assert!(wallet.version == CURRENT_VERSION, E_INVALID_VERSION);
        assert!(wallet.recovery_key == recovery_signer, E_UNAUTHORIZED);

        // Clear members and reverse‑index entries
        let old_members = wallet.members;
        let keys = vec_map::keys(&old_members);
        let mut i = 0;
        while (i < vector::length(&keys)) {
            let member = vector::borrow(&keys, i);
            member_index::remove_wallet_for_member(*member, id_address(wallet));
            i = i + 1;
        };
        wallet.members = vec_map::empty();

        // Insert the new admin
        let role = Role { name: role_name, weight, permissions };
        vec_map::insert(&mut wallet.members, new_signer, role);
        df::add(&mut wallet.id, b"pubkey_" ++ bcs::to_bytes(&new_signer), pubkey);

        // Re‑compute deterministic ID (now based on a single member)
        helpers::store_multisig_id(wallet);

        // Update reverse index for the fresh admin
        member_index::add_wallet_for_member(new_signer, id_address(wallet));
    }

    /// Generic extension point – callers can store any arbitrary key/value
    /// pair inside the wallet’s dynamic‑field namespace.
    public entry fun add_extension(
        wallet: &mut SmartWallet,
        key: vector<u8>,
        value: vector<u8>,
        auth_signer: address,
        ctx: &mut TxContext,
    ) {
        assert!(wallet.version == CURRENT_VERSION, E_INVALID_VERSION);
        assert!(
            vec_map::contains(&wallet.members, &auth_signer) || wallet.recovery_key == auth_signer,
            E_UNAUTHORIZED
        );
        df::add(&mut wallet.id, key, value);
    }

    // ──────────────────────────────────────────────────────────────
    // PUBLIC VIEW‑ONLY HELPERS
    // ──────────────────────────────────────────────────────────────
    public fun get_wallet_version(wallet: &SmartWallet): u64 {
        wallet.version
    }

    public fun list_proposals(wallet: &SmartWallet): vector<u64> {
        vec_map::keys(&wallet.proposals)
    }

    public fun get_proposal(wallet: &SmartWallet, pid: u64): Proposal {
        vec_map::get(&wallet.proposals, &pid)
    }

    // ──────────────────────────────────────────────────────────────
    // INTERNAL HELPERS (pure, no gas)
    // ──────────────────────────────────────────────────────────────
    fun sum_weights(members: &VecMap<address, Role>): u64 {
        let keys = vec_map::keys(members);
        let mut total: u64 = 0;
        let mut i = 0;
        while (i < vector::length(&keys)) {
            let member = vector::borrow(&keys, i);
            let role = vec_map::get(members, member);
            total = utils::safe_add_u64(total, role.weight);
            i = i + 1;
        };
        total
    }
}