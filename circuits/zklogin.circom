pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/bitify.circom";

// Minimal zkLogin circuit: proves the relationship between hashed JWT claims,
// salt field element, and the resulting zkLogin address seed commitment.
template SuiZkLoginMinimal() {
    // Private inputs
    signal input claim_name_hash;   // hashASCIIStrToField('sub', 32)
    signal input claim_value_hash;  // hashASCIIStrToField(claims.sub, 115)
    signal input aud_hash;          // hashASCIIStrToField(aud, 145)
    signal input salt_field;        // Salt reduced into BN254 field
    signal input intent_data;       // Intent hash pre-image (field element)

    // Public signals
    signal input address_seed;      // Poseidon(claim_name_hash, claim_value_hash, aud_hash, poseidon(salt_field))
    signal input intent_hash;       // Poseidon(intent_data)

    // Bind proof to intent payload
    component intentHasher = Poseidon(1);
    intentHasher.inputs[0] <== intent_data;
    intent_hash === intentHasher.out;

    // Hash salt field element for seed derivation
    component saltHasher = Poseidon(1);
    saltHasher.inputs[0] <== salt_field;

    // Derive address seed exactly as Mysten SDK does
    component addressSeed = Poseidon(4);
    addressSeed.inputs[0] <== claim_name_hash;
    addressSeed.inputs[1] <== claim_value_hash;
    addressSeed.inputs[2] <== aud_hash;
    addressSeed.inputs[3] <== saltHasher.out;
    address_seed === addressSeed.out;

    // Range checks to ensure inputs lie inside BN254 field
    component claimNameBits = Num2Bits(254);
    claimNameBits.in <== claim_name_hash;
    component claimValueBits = Num2Bits(254);
    claimValueBits.in <== claim_value_hash;
    component audBits = Num2Bits(254);
    audBits.in <== aud_hash;
    component saltBits = Num2Bits(254);
    saltBits.in <== salt_field;
    component intentBits = Num2Bits(254);
    intentBits.in <== intent_data;
}

component main { public [address_seed, intent_hash] } = SuiZkLoginMinimal();
