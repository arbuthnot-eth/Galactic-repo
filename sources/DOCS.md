# vWallet Core - Smart Multi-Signature Wallet Documentation

## Overview

vWallet Core is a sophisticated smart contract system built on Sui Move that implements a multi-signature wallet with advanced features. Think of it as a digital vault that requires multiple people to agree before any transaction can be executed, providing enhanced security for shared funds and decision-making.

## Core Concepts

### What is a Multi-Signature Wallet?

A multi-signature (multisig) wallet is like a bank vault that requires multiple keys to open. Instead of one person having complete control over funds, multiple trusted parties (called "members") must approve transactions before they can be executed.

**Example:** A company treasury might require 3 out of 5 board members to approve any payment over $10,000.

## System Architecture

The vWallet system consists of three main modules:

### 1. Wallet Module (`wallet.move`)
The core module containing the main wallet functionality.

### 2. Member Index Module (`member_index.move`) 
A registry system that tracks which wallets each member belongs to.

### 3. Helper Functions
Utility functions integrated into the wallet module for supporting operations.

## Key Components Explained

### SmartWallet Structure

```move
public struct SmartWallet has key, store {
    id: UID,                           // Unique identifier
    name: vector<u8>,                  // Human-readable name
    version: u64,                      // Version for upgrades
    members: VecMap<address, Role>,    // Who can use this wallet
    proposals: VecMap<u64, Proposal>,  // Pending transactions
    created_at: u64,                   // When it was created
    recovery_key: address,             // Emergency recovery address
}
```

**In Simple Terms:**
- `id`: Like a social security number for the wallet
- `name`: A friendly name like "Company Treasury" or "Family Savings"
- `members`: List of people who can vote on transactions
- `proposals`: Pending transactions waiting for approval
- `recovery_key`: Emergency contact who can help if things go wrong

### Member Roles

```move
public struct Role has store, copy, drop {
    weight: u64,      // Voting power (like number of shares)
    permissions: u64, // What they're allowed to do
}
```

**Example Roles:**
- **CEO**: Weight 3, Full permissions
- **CFO**: Weight 2, Financial permissions  
- **Board Member**: Weight 1, Voting permissions

### Proposals System

Every transaction must go through a proposal process:

```move
public struct Proposal has store {
    id: u64,                              // Proposal number
    proposer: address,                    // Who suggested it
    action: Action,                       // What to do
    approvals: VecMap<address, u64>,      // Who voted yes
    conditions: vector<Condition>,        // Special requirements
    deadline: u64,                        // When it expires
    executed: bool,                       // Whether it's been done
    total_weight: u64,                    // Total votes so far
    threshold: u64,                       // Votes needed to pass
}
```

### Actions and Conditions

**Actions** define what the wallet will do:
```move
public struct Action has store, drop {
    kind: vector<u8>,    // Type: "transfer", "add_member", etc.
    target: address,     // Who/what is affected
    data: vector<u8>,    // Additional information
}
```

**Conditions** add requirements:
```move
public struct Condition has store, drop {
    kind: vector<u8>,    // Type: "block_height", "oracle", etc.
    value: vector<u8>,   // The requirement details
}
```

## Main Functions Explained

### Creating a Wallet

```move
public entry fun create_wallet(
    name: vector<u8>,
    members_addresses: vector<address>,
    members_roles: vector<Role>,
    recovery_key: address,
    ctx: &mut TxContext,
)
```

**What it does:** Sets up a new shared wallet
**Who can call it:** Anyone
**Example:** Create "Family Vacation Fund" with Mom, Dad, and Grandma as members

### Adding Members

```move
public entry fun add_member(
    wallet: &mut SmartWallet,
    new_signer: address,
    role: Role,
    pubkey: vector<u8>,
    ctx: &mut TxContext,
)
```

**What it does:** Adds a new person to the wallet
**Who can call it:** Existing wallet members
**Real-world example:** Adding a new business partner to company wallet

### Proposing Actions

```move
public fun propose_action(
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
)
```

**What it does:** Suggests a new transaction or action
**Example:** "I propose we send $5,000 to the charity (address: 0x123...)"

### Approving Proposals

```move
public entry fun approve_proposal(
    wallet: &mut SmartWallet,
    proposal_id: u64,
    clock: &Clock,
    ctx: &mut TxContext,
)
```

**What it does:** Vote "yes" on a pending proposal
**Security:** Only wallet members can approve
**Example:** Board member votes to approve the charity donation

### Executing Proposals

```move
public entry fun execute_proposal(
    wallet: &mut SmartWallet,
    proposal_id: u64,
    clock: &Clock,
    ctx: &mut TxContext,
)
```

**What it does:** Carries out an approved proposal
**Requirements:** Must have enough votes and meet all conditions
**Example:** Actually sends the $5,000 to charity after approval

## Security Features

### 1. Multi-Signature Protection
- No single person can move funds alone
- Requires multiple approvals based on voting weights
- Prevents unauthorized access even if one key is compromised

### 2. Proposal System
- All actions must be proposed first
- Transparent voting process
- Built-in delays allow for review

### 3. Conditional Execution
- Actions can have requirements (time locks, external conditions)
- Prevents hasty decisions
- Allows for oracle integration

### 4. Recovery Mechanism
- Recovery key can help in emergencies
- Prevents permanent loss of funds
- Controlled by trusted party

### 5. Member Management
- Add/remove members through proposals
- Adjust voting weights as needed
- Maintain access control

## Real-World Use Cases

### 1. Corporate Treasury
**Scenario:** Tech startup with $2M in treasury
**Setup:** 
- 5 board members
- Requires 3/5 approval for transactions > $50K
- CFO has higher voting weight
- 24-hour delay on large transactions

### 2. Family Inheritance
**Scenario:** Family managing inherited assets
**Setup:**
- 3 siblings as equal members
- Requires 2/3 approval for any transaction
- Lawyer as recovery key
- Annual spending limits

### 3. DAO Treasury
**Scenario:** Decentralized organization funds
**Setup:**
- Token holders as members
- Voting weight based on token holdings
- Time-locked proposals for governance
- Community-elected recovery committee

### 4. Investment Club
**Scenario:** Group of friends investing together
**Setup:**
- 10 members with equal weight
- Requires 60% approval for investments
- Quarterly rebalancing proposals
- Exit mechanism for members

## Technical Implementation Details

### Dynamic Field Storage
- Uses Sui's dynamic fields for flexible data storage
- Stores member pubkeys for multisig verification
- Efficient storage and retrieval of wallet metadata

### Event System
- Emits events for all major actions
- Enables off-chain indexing and monitoring
- Provides audit trail for compliance

### Upgrade Path
- Version tracking for contract upgrades
- Backward compatibility considerations
- Migration strategies for existing wallets

## Integration Guidelines

### For Frontend Developers
1. **Wallet Creation**: Call `create_wallet` with member list
2. **Proposal Management**: Use `propose_action` → `approve_proposal` → `execute_proposal` flow
3. **Event Monitoring**: Listen for wallet events to update UI
4. **Member Management**: Handle add/remove member workflows

### For Backend Services
1. **Indexing**: Monitor events for transaction history
2. **Notifications**: Alert members of new proposals
3. **Analytics**: Track voting patterns and wallet usage
4. **Compliance**: Generate reports from audit trail

## Best Practices

### Security
- Use hardware wallets for member keys
- Regularly review and rotate recovery keys
- Set appropriate voting thresholds
- Implement time delays for large transactions

### Governance
- Clearly define member roles and responsibilities
- Establish voting procedures and quorum requirements
- Regular review of member list and permissions
- Document decision-making processes

### Technical
- Test all operations on devnet first
- Monitor gas costs and optimize batch operations
- Implement proper error handling
- Regular backup of wallet configurations

## Troubleshooting

### Common Issues
1. **Insufficient Approvals**: Check voting weights and thresholds
2. **Expired Proposals**: Proposals have deadlines - recreate if needed
3. **Permission Denied**: Verify caller is wallet member
4. **Condition Not Met**: Check time locks and external requirements

### Error Codes
- `E_NOT_MEMBER`: Caller is not a wallet member
- `E_INVALID_ROLE`: Role configuration is incorrect
- `E_ALREADY_APPROVED`: Member already voted on proposal
- `E_INSUFFICIENT_APPROVALS`: Not enough votes to execute
- `E_EXPIRED_PROPOSAL`: Proposal deadline has passed

## Future Enhancements

### Planned Features
1. **Multi-chain Support**: Cross-chain transaction capabilities
2. **Advanced Conditions**: Integration with price oracles
3. **Batch Transactions**: Execute multiple actions atomically
4. **Delegation**: Allow members to delegate voting power
5. **Templates**: Pre-configured wallet types for common use cases

### Integration Opportunities
1. **DeFi Protocols**: Direct integration with lending/trading
2. **NFT Marketplaces**: Collective NFT purchasing and management
3. **Governance Platforms**: Integration with DAO voting systems
4. **Enterprise Software**: API for business workflow integration

## Conclusion

vWallet Core provides a robust, secure, and flexible foundation for multi-signature wallet functionality on Sui. Its modular design, comprehensive security features, and extensible architecture make it suitable for a wide range of use cases from personal finance to enterprise treasury management.

The system prioritizes security through its multi-signature approach while maintaining usability through its proposal-based workflow. By requiring multiple approvals and supporting conditional execution, vWallet helps prevent unauthorized access while enabling collaborative financial decision-making.

Whether you're building a simple family wallet or a complex DAO treasury, vWallet Core provides the tools and security features needed to manage shared funds safely and efficiently.