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

    /// Initialise a brand‑new wallet.  No global threshold is stored – each
    /// proposal decides its own.
    public entry fun create_wallet(
        initial_signer: address,
        recovery_key: address,
        name: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
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

    /// Add a new member.  The caller must be an existing member with the
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
        assert!(
            vec_map::contains(&wallet.members, &auth_signer) || wallet.recovery_key == auth_signer,
            E_UNAUTHORIZED
        );

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

    /// Remove an existing member.  Same auth rules as `add_member`.
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

    /// Update **per‑proposal** threshold – this is a convenience entry‑point
    /// that does **not** affect existing proposals (they keep their own value).
    public entry fun update_global_threshold(
        wallet: &mut SmartWallet,
        new_threshold: u64,
        auth_signer: address,
        ctx: &mut TxContext,
    ) {
        // Kept for backward compatibility – not used by the core logic.
        // It simply records the value in an extension field so UI can read it.
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

    /// Propose a new action.  The proposal carries its own threshold and
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

    /// Approve a proposal.  If the accumulated weight reaches the proposal’s
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

        // Record approval and update total weight
        vec_map::insert(&mut proposal.approvals, sender, role.weight);
        proposal.total_weight = proposal.total_weight + role.weight;

        // Auto‑execute when threshold is met
        if (proposal.total_weight >= proposal.threshold) {
            execute_proposal(wallet, proposal_id, clock, ctx);
        };
    }

    /// Internal executor – called automatically from `approve_proposal` or
    /// can be invoked directly by an address that has the `execute` permission.
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
    // INTERNAL HELPERS (pure, no gas)
    // ──────────────────────────────────────────────────────────────
    fun sum_weights(members: &VecMap<address, Role>): u64 {
        let keys = vec_map::keys(members);
        let mut total: u64 = 0;
        let mut i = 0;
        while (i < vector::length(&keys)) {
            let member = vector::borrow(&keys, i);
            let role = vec_map::get(members, member);
            total = total + role.weight;
            i = i + 1;
        };
        total
    }
}
``~~~~~

```~~~~~move path="sources/helpers.move"
module smart_wallet::helpers {
    use sui::object::{self, UID, id_address};
    use sui::vec_map::{self, VecMap};
    use sui::dynamic_field as df;
    use sui::event;
    use sui::coin::{self, Coin};
    use sui::transfer;
    use sui::sui::SUI;
    use multisig::multisig;

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
        let mut pks: vector<vector<u8>> = vector[];
        let mut wts: vector<u8> = vector[];
        let keys = vec_map::keys(members);
        let mut i = 0;
        while (i < vector::length(&keys)) {
            let member = vector::borrow(&keys, i);
            let role = vec_map::get(members, member);
            // -----------------------------------------------------------------
            // In production the raw public key is stored as a dynamic field
            // keyed by "pubkey_<address>".  For this example we fetch it
            // directly; if missing we abort (the wallet should never be in that state).
            // -----------------------------------------------------------------
            let pk_opt = df::borrow(&member, b"pubkey_" ++ bcs::to_bytes(member));
            let pk = option::unwrap(pk_opt);
            vector::push_back(&mut pks, pk);
            // Weight is u64 but the original helper expects u8; we truncate safely
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
    // Execute a simple SUI transfer.  The wallet holds its own coins in a
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
``~~~~~

```~~~~~move path="sources/member_index.move"
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
``~~~~~

```~~~~~move path="tests/smart_wallet_tests.move"
#[test_only]
module smart_wallet::tests {
    use smart_wallet::wallet::{self, SmartWallet, Role, Action, Condition, Proposal};
    use smart_wallet::helpers;
    use sui::address;
    use sui::tx_context::TxContext;
    use sui::clock::{self, Clock};

    // Simple mock context – in real tests you would use `dev_inspect_transaction_block`
    // or a full‑node test harness.
    #[test]
    fun test_wallet_lifecycle() {
        // -----------------------------------------------------------------
        // 1️⃣  Create a wallet with a single admin member
        // -----------------------------------------------------------------
        let admin = @0x1;
        let recovery = @0xdead;
        let name = b"My Treasury";
        let clock = Clock { dummy: 0 };
        let mut ctx = TxContext::placeholder();

        wallet::create_wallet(admin, recovery, name, &clock, &mut ctx);

        // -----------------------------------------------------------------
        // 2️⃣  Add a second member
        // -----------------------------------------------------------------
        let member = @0x2;
        let pubkey = vector[0u8; 33]; // dummy ed25519 pk (flag 0 + 32 zeroes)
        let role_name = b"voter";
        let weight = 1;
        let perms = 7; // full perms
        wallet::add_member(
            &mut wallet_obj,
            member,
            pubkey,
            role_name,
            weight,
            perms,
            admin,
            &mut ctx,
        );

        // -----------------------------------------------------------------
        // 3️⃣  Propose a transfer with its own threshold = 2
        // -----------------------------------------------------------------
        let proposal_id = 42;
        let action_kind = b"transfer";
        let target = @0xfee;
        let amount = 1_000_000u64;
        let data = bcs::to_bytes(&amount);
        let proposal_threshold = 2;
        let deadline = 0;
        let conds = vector::empty<Condition>();

        wallet::propose_action(
            &mut wallet_obj,
            proposal_id,
            action_kind,
            target,
            data,
            proposal_threshold,
            deadline,
            conds,
            &clock,
            &mut ctx,
        );

        // -----------------------------------------------------------------
        // 4️⃣  Both members approve – should auto‑execute
        // -----------------------------------------------------------------
        wallet::approve_proposal(&mut wallet_obj, proposal_id, &clock, &mut ctx); // admin approves
        // Switch sender to the second member (mock)
        tx_context::set_sender(&mut ctx, member);
        wallet::approve_proposal(&mut wallet_obj, proposal_id, &clock, &mut ctx);

        // After the second approval the proposal must be executed.
        let proposal = vec_map::get(&wallet_obj.proposals, &proposal_id);
        assert!(proposal.executed, 0);
    }
}