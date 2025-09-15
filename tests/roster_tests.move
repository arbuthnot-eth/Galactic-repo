#[test_only]
module vwallet::roster_tests {
    use vwallet::roster;
    use vwallet::core;
    use sui::test_scenario as ts;
    use sui::clock;
    use sui::object::id_address;

    #[test]
    fun test_direct_add_and_list_wallets() {
        let admin = @0x1;
        let mut scenario = ts::begin(admin);
        let mut reg = roster::create_roster_for_testing(ts::ctx(&mut scenario));
        let w1 = @0xAAA1;
        let w2 = @0xAAA2;

        // add wallets for a member
        roster::add_wallet_for_member(&mut reg, admin, w1, ts::ctx(&mut scenario));
        roster::add_wallet_for_member(&mut reg, admin, w2, ts::ctx(&mut scenario));

        let ws = roster::wallets_of(&reg, admin);
        assert!(vector::length(&ws) == 2, 0);

        // Duplicate add is ignored
        roster::add_wallet_for_member(&mut reg, admin, w2, ts::ctx(&mut scenario));
        let ws2 = roster::wallets_of(&reg, admin);
        assert!(vector::length(&ws2) == 2, 1);

        roster::destroy_roster_for_testing(reg);
        ts::end(scenario);
    }

    #[test]
    fun test_remove_wallet_for_member_and_cleanup() {
        let admin = @0x1;
        let mut scenario = ts::begin(admin);
        let mut reg = roster::create_roster_for_testing(ts::ctx(&mut scenario));
        let w1 = @0xB001;
        roster::add_wallet_for_member(&mut reg, admin, w1, ts::ctx(&mut scenario));
        let ws = roster::wallets_of(&reg, admin);
        assert!(vector::length(&ws) == 1, 0);

        // Remove the only wallet; the member entry should be cleaned
        roster::remove_wallet_for_member(&mut reg, admin, w1);
        let ws_after = roster::wallets_of(&reg, admin);
        assert!(vector::length(&ws_after) == 0, 1);

        roster::destroy_roster_for_testing(reg);
        ts::end(scenario);
    }

    #[test]
    fun test_roster_integration_with_core_add_remove() {
        let admin = @0x1;
        let m2 = @0x2;
        let recovery = @0x3;
        let mut scenario = ts::begin(admin);
        let clock_obj = clock::create_for_testing(ts::ctx(&mut scenario));
        let mut reg = roster::create_roster_for_testing(ts::ctx(&mut scenario));

        let mut wallet = core::create_wallet(admin, recovery, b"Roster Int", &clock_obj, ts::ctx(&mut scenario));
        let wid = id_address(&wallet);

        // Add member via core; roster should reflect it
        core::add_member(&mut wallet, &mut reg, m2, b"member", 1, 7, admin, ts::ctx(&mut scenario));
        let ws = roster::wallets_of(&reg, m2);
        assert!(vector::length(&ws) == 1, 0);
        assert!(*vector::borrow(&ws, 0) == wid, 1);

        // Remove member via core; roster should remove it
        core::remove_member(&mut wallet, &mut reg, m2, admin, ts::ctx(&mut scenario));
        let ws_after = roster::wallets_of(&reg, m2);
        assert!(vector::length(&ws_after) == 0, 2);

        sui::transfer::public_transfer(wallet, admin);
        roster::destroy_roster_for_testing(reg);
        clock::destroy_for_testing(clock_obj);
        ts::end(scenario);
    }
}

