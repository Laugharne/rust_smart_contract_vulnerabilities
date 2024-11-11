# Top Rust Smart Contract Vulnerabilities: A Deep Dive with Examples

> **Source:** [Top Rust Smart Contract Vulnerabilities: A Deep Dive with Examples](https://medium.com/@dehvcurtis/top-rust-smart-contract-vulnerabilities-a-deep-dive-with-examples-eb36a84c800b)

Rust has quickly become a favored language for smart contract development on blockchain platforms such as **NEAR Protocol** , **Polkadot** and **Solana** due to its strong safety guarantees and memory management features. However, smart contracts written in Rust are still prone to a range of vulnerabilities, just like in other blockchain development languages.

This article will explore some of the **top vulnerabilities** in Rust smart contracts and provide examples to illustrate these issues, along with best practices for mitigation.

## Unchecked Integer Overflow/Underflow

Integer overflow occurs when a value exceeds the maximum for a type, while underflow occurs when it falls below the minimum (e.g., a subtraction leading to a negative value in an unsigned integer).

By default, Rust's integer arithmetic is safe in debug mode, but in release mode, it behaves similarly to languages like C, where overflows wrap around, which can lead to unexpected behavior.

**Vulnerable Example:**

```rust
fn main() {
    let mut balance: u64 = 10;
    balance -= 20; // Underflow
    println!("Balance: {}", balance); // This will panic in debug mode
}
```

**Mitigation**: Use Rust's `checked_*` or `saturating_*` methods to safely handle overflows and underflows:

```rust
fn main() {
    let balance: u64 = 10;
    let new_balance = balance.checked_sub(20).expect("Subtraction overflowed!");
    println!("New Balance: {}", new_balance);
}
```

## Reentrancy Attacks

Reentrancy attacks occur when an external contract calls back into the vulnerable contract before the original function call is completed, potentially allowing the external contract to alter the state unexpectedly (such as withdrawing funds multiple times).

**Example**:

```rust
pub fn withdraw(&mut self, amount: u128) {
    assert!(self.balances[self.caller()] >= amount, "Insufficient funds");
    self.transfer(self.caller(), amount);
    self.balances[self.caller()] -= amount;  // Reentrancy vulnerability
}
```

In this case, if `self.transfer()` calls into another contract that can recursively call `withdraw()`, it could repeatedly drain funds.

**Mitigation**: Use the **checks-effects-interactions** pattern, updating the state before making external calls:

```rust
pub fn withdraw(&mut self, amount: u128) {
    assert!(self.balances[self.caller()] >= amount, "Insufficient funds");
    self.balances[self.caller()] -= amount;  // Update state first
    self.transfer(self.caller(), amount);    // Then make the external call
}
```

## Unrestricted Access to Critical Functions

**Description**: Critical functions that are not properly restricted by access control can be executed by anyone, leading to unauthorized fund transfers or administrative actions.

**Example**:

```rust
pub fn set_admin(&mut self, new_admin: AccountId) {
    self.admin = new_admin; // Anyone can call this and set themselves as admin
}
```

**Mitigation**: Ensure proper access control by restricting function execution to only authorized users:

```rust
pub fn set_admin(&mut self, new_admin: AccountId) {
    assert_eq!(self.admin, self.caller(), "Unauthorized");
    self.admin = new_admin;
}
```

## Unchecked External Calls

**Description**: External calls can fail for many reasons, such as the called contract being non-existent or out of gas. If the result of these calls is not checked, it can lead to silent failures that are not handled, leaving the contract in an inconsistent state.

**Example**:

```rust
pub fn perform_external_call(&self, contract_id: AccountId) {
    let result = env::promise_create(
        contract_id,
        "some_function",
        &json!({}).to_string().into_bytes(),
        0,
        env::prepaid_gas(),
    );
    // If `result` fails, the contract doesn't handle it
}
```

**Mitigation**: Always check the outcome of external contract calls:

```rust
pub fn perform_external_call(&self, contract_id: AccountId) {
    let result = env::promise_create(
        contract_id,
        "some_function",
        &json!({}).to_string().into_bytes(),
        0,
        env::prepaid_gas(),
    );
    assert!(result.is_ok(), "External call failed"); }
```

## Unbounded Loops and High Gas Consumption

**Description**: Smart contracts operate within gas limits. If a contract has loops that can iterate indefinitely or over large datasets, it may exceed the gas limit, causing the transaction to fail or the contract to be unusable.

**Example**:

```rust
pub fn sum_values(&self, values: Vec<u128>) -> u128 {
    let mut sum = 0;
    for value in values {
        sum += value;  // This loop can be too expensive if `values` is large
    }
    sum
}
```

**Mitigation**: Avoid unbounded loops or large iterations. Consider using batching techniques:

```rust
pub fn sum_values_in_batches(&self, values: Vec<u128>, batch_size: usize) -> u128 {
    let mut sum = 0;
    for value in values.iter().take(batch_size) {
        sum += value;
    }
    sum
}
```

## Storage Attacks (Denial of Service)

**Description**: In a storage-based denial of service (DoS) attack, an attacker can exploit an inefficient storage mechanism to inflate the contract's storage, incurring large storage fees or even causing the contract to run out of storage.

**Example**:

```rust
pub fn add_to_list(&mut self, item: u128) {
    self.list.push(item);  // Unbounded storage growth
}
```

**Mitigation**: Use efficient storage structures like `BTreeMap` for more scalable storage and apply limits:

```rust
pub fn add_to_list(&mut self, item: u128) {     assert!(self.list.len() < 100, "List is full");     self.list.push(item); }
```

## Floating-Point Precision Errors

**Description**: Floating-point arithmetic can introduce rounding errors, which is dangerous when handling financial transactions in smart contracts. Rust's floating-point types, `f32` and `f64`, are not suitable for precise financial calculations.

**Example**:

```rust
let amount: f64 = 1.1 + 2.2;  // May not exactly equal 3.3 due to precision errors
```

**Mitigation**: Avoid using floating-point numbers for financial calculations. Instead, use integers to represent the smallest units (e.g., `wei` in Ethereum or `lamports` in Solana):

```rust
let amount: u64 = 110 + 220;  // Use integers to maintain precision
```

## State Manipulation in Asynchronous Operations

**Description**: Contracts may perform asynchronous operations like cross-contract calls. If the state is not validated after these operations, malicious actors can manipulate the contract state during execution.

**Example**:

```rust
pub fn async_operation(&mut self) {
    let initial_state = self.state;
    env::promise_create("another_contract", "external_call", &[], 0, env::prepaid_gas());
    assert_eq!(self.state, initial_state);  // State could have changed unexpectedly
}
```

**Mitigation**: Re-validate the contract's state after asynchronous calls and ensure changes are expected.

## Improper Initialization of Contract State

**Description**: Smart contracts that don't properly initialize their state can leave critical variables in an uninitialized or default state, leading to security issues.

**Example**:

```rust
pub fn new() -> Self {
    Self {
        admin: Default::default(), // Could lead to undefined behavior
    }
}
```

**Mitigation**: Ensure that all state variables are initialized correctly during the contract's deployment:

```rust
pub fn new(admin: AccountId) -> Self {
    Self {
        admin: admin, // Explicitly initialize the admin
    }
}
```

## Conclusion:

Rust's safety features, such as its ownership and type system, can prevent many common issues in smart contract development. However, even in Rust, developers must remain vigilant about smart contract-specific vulnerabilities such as reentrancy attacks, integer overflow, and gas consumption limits.

By following best practices and carefully structuring your contract's code, you can write robust, secure Rust smart contracts that stand the test of time in decentralized systems.