#[test_only]
module vwallet::core_tests {
    use vwallet::core;
    use vwallet::roster;
    use sui::test_scenario as ts;
    use sui::clock;
    use sui::coin;
    use sui::sui::SUI;
    use sui::bcs;
    use sui::object::id_address;

    #[test]
    fun test_wallet_creation() {
        let admin = @0x1;
        let recovery_key = @0x2;
        let mut scenario = ts::begin(admin);
        let clock_obj = clock::create_for_testing(ts::ctx(&mut scenario));

        let wallet = core::create_wallet(
            admin,
            recovery_key,
            b"Test Wallet",
            &clock_obj,
            ts::ctx(&mut scenario)
        );

        assert!(core::get_wallet_version(&wallet) == 1, 0);
        assert!(core::get_balance(&wallet) == 0, 1);

        sui::transfer::public_transfer(wallet, admin);
        clock::destroy_for_testing(clock_obj);
        ts::end(scenario);
    }

    #[test]
    fun test_deposit_withdraw() {
        let admin = @0x1;
        let recovery_key = @0x2;
        let mut scenario = ts::begin(admin);
        let clock_obj = clock::create_for_testing(ts::ctx(&mut scenario));

        let mut wallet = core::create_wallet(
            admin,
            recovery_key,
            b"Test Wallet",
            &clock_obj,
            ts::ctx(&mut scenario)
        );

        assert!(core::get_balance(&wallet) == 0, 0);
        let c = coin::mint_for_testing<SUI>(1000, ts::ctx(&mut scenario));
        core::deposit(&mut wallet, c, ts::ctx(&mut scenario));
        assert!(core::get_balance(&wallet) == 1000, 1);

        let wcoin = core::withdraw(&mut wallet, 300, admin, ts::ctx(&mut scenario));
        assert!(coin::value(&wcoin) == 300, 2);
        assert!(core::get_balance(&wallet) == 700, 3);
        coin::burn_for_testing(wcoin);

        sui::transfer::public_transfer(wallet, admin);
        clock::destroy_for_testing(clock_obj);
        ts::end(scenario);
    }

    #[test]
    fun test_member_operations() {
        let admin = @0x1;
        let new_member = @0x3;
        let recovery_key = @0x2;
        let mut scenario = ts::begin(admin);
        let clock_obj = clock::create_for_testing(ts::ctx(&mut scenario));
        let mut reg = roster::create_roster_for_testing(ts::ctx(&mut scenario));

        let mut wallet = core::create_wallet(
            admin,
            recovery_key,
            b"Test Wallet",
            &clock_obj,
            ts::ctx(&mut scenario)
        );

        core::add_member(
            &mut wallet,
            &mut reg,
            new_member,
            b"member",
            2,
            3,
            admin,
            ts::ctx(&mut scenario)
        );

        let ws = roster::wallets_of(&reg, new_member);
        assert!(vector::length(&ws) == 1, 100);
        assert!(*vector::borrow(&ws, 0) == id_address(&wallet), 101);

        core::remove_member(
            &mut wallet,
            &mut reg,
            new_member,
            admin,
            ts::ctx(&mut scenario)
        );

        sui::transfer::public_transfer(wallet, admin);
        roster::destroy_roster_for_testing(reg);
        clock::destroy_for_testing(clock_obj);
        ts::end(scenario);
    }

    #[test]
    fun test_proposal_workflow() {
        let admin = @0x1;
        let member = @0x3;
        let recovery_key = @0x2;
        let mut scenario = ts::begin(admin);
        let clock_obj = clock::create_for_testing(ts::ctx(&mut scenario));
        let mut reg = roster::create_roster_for_testing(ts::ctx(&mut scenario));

        let mut wallet = core::create_wallet(
            admin,
            recovery_key,
            b"Test Wallet",
            &clock_obj,
            ts::ctx(&mut scenario)
        );

        core::add_member(
            &mut wallet,
            &mut reg,
            member,
            b"member",
            1,
            7,
            admin,
            ts::ctx(&mut scenario)
        );

        let proposal_id = 1;
        let target = @0x999;
        let amount_bytes = bcs::to_bytes(&100u64);

        ts::next_tx(&mut scenario, admin);
        core::propose_action(
            &mut wallet,
            proposal_id,
            b"transfer",
            target,
            amount_bytes,
            2,
            0,
            vector[],
            &clock_obj,
            ts::ctx(&mut scenario)
        );
        assert!(core::proposal_exists(&wallet, proposal_id), 0);
        let proposals = core::list_proposals(&wallet);
        assert!(vector::length(&proposals) == 1, 1);

        sui::transfer::public_transfer(wallet, admin);
        roster::destroy_roster_for_testing(reg);
        clock::destroy_for_testing(clock_obj);
        ts::end(scenario);
    }

    #[test]
    fun test_comprehensive_proposal_flow() {
        let admin = @0x1;
        let member = @0x3;
        let recovery_key = @0x2;
        let mut scenario = ts::begin(admin);
        let clock_obj = clock::create_for_testing(ts::ctx(&mut scenario));
        let mut reg = roster::create_roster_for_testing(ts::ctx(&mut scenario));

        let mut wallet = core::create_wallet(
            admin,
            recovery_key,
            b"Test Wallet",
            &clock_obj,
            ts::ctx(&mut scenario)
        );

        core::add_member(
            &mut wallet,
            &mut reg,
            member,
            b"member",
            1,
            7,
            admin,
            ts::ctx(&mut scenario)
        );

        // Fund wallet so the transfer action can execute
        let cfund = coin::mint_for_testing<SUI>(500, ts::ctx(&mut scenario));
        core::deposit(&mut wallet, cfund, ts::ctx(&mut scenario));

        let proposal_id = 1;
        let target = @0x999;
        let amount_bytes = bcs::to_bytes(&100u64);

        ts::next_tx(&mut scenario, admin);
        core::propose_action(
            &mut wallet,
            proposal_id,
            b"transfer",
            target,
            amount_bytes,
            2,
            0,
            vector[],
            &clock_obj,
            ts::ctx(&mut scenario)
        );

        ts::next_tx(&mut scenario, admin);
        core::approve_proposal(&mut wallet, proposal_id, &clock_obj, ts::ctx(&mut scenario));

        ts::next_tx(&mut scenario, member);
        core::approve_proposal(&mut wallet, proposal_id, &clock_obj, ts::ctx(&mut scenario));

        sui::transfer::public_transfer(wallet, admin);
        roster::destroy_roster_for_testing(reg);
        clock::destroy_for_testing(clock_obj);
        ts::end(scenario);
    }

    #[test]
    fun test_comprehensive_balance_operations() {
        let admin = @0x1;
        let recovery_key = @0x2;
        let mut scenario = ts::begin(admin);
        let clock_obj = clock::create_for_testing(ts::ctx(&mut scenario));

        let mut wallet = core::create_wallet(
            admin,
            recovery_key,
            b"Test Wallet",
            &clock_obj,
            ts::ctx(&mut scenario)
        );

        assert!(core::get_balance(&wallet) == 0, 0);
        let c = coin::mint_for_testing<SUI>(1000, ts::ctx(&mut scenario));
        core::deposit(&mut wallet, c, ts::ctx(&mut scenario));
        assert!(core::get_balance(&wallet) == 1000, 1);

        let w = core::withdraw(&mut wallet, 300, admin, ts::ctx(&mut scenario));
        assert!(coin::value(&w) == 300, 2);
        assert!(core::get_balance(&wallet) == 700, 3);
        coin::burn_for_testing(w);

        sui::transfer::public_transfer(wallet, admin);
        clock::destroy_for_testing(clock_obj);
        ts::end(scenario);
    }

    #[test]
    fun test_multisig_id_generation() {
        let admin = @0x1;
        let recovery_key = @0x2;
        let mut scenario = ts::begin(admin);
        let clock_obj = clock::create_for_testing(ts::ctx(&mut scenario));
        let mut reg = roster::create_roster_for_testing(ts::ctx(&mut scenario));

        let mut wallet = core::create_wallet(
            admin,
            recovery_key,
            b"Test Wallet",
            &clock_obj,
            ts::ctx(&mut scenario)
        );

        core::add_member(
            &mut wallet,
            &mut reg,
            @0x3,
            b"member",
            1,
            3,
            admin,
            ts::ctx(&mut scenario)
        );

        // Just ensure it runs
        let _ = core::compute_multisig_id_for_wallet(&wallet, 1);

        sui::transfer::public_transfer(wallet, admin);
        roster::destroy_roster_for_testing(reg);
        clock::destroy_for_testing(clock_obj);
        ts::end(scenario);
    }
}
