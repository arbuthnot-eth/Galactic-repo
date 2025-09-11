module smart_wallet::utils {
    /// Safe addition for `u64`.  Returns the sum if no overflow, otherwise aborts.
    public fun safe_add_u64(a: u64, b: u64): u64 {
        let (sum, overflow) = u64::add_with_overflow(a, b);
        assert!(!overflow, 0xFFFFFFFFFFFFFFFF); // generic overflow error code
        sum
    }

    /// Helper to convert a `vector<u8>` address to the canonical `address` type.
    public fun addr_from_bytes(b: &vector<u8>): address {
        bcs::from_bytes<address>(b)
    }
}