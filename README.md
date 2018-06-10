# Purity in EVM Code

_This document seeks to define purity in the context of an Ethereum smart
contract. Based upon this definition it then identifies which opcodes are
impure and those which are pure or impure depending on their use._

**This document is a work-in-progress and is not official advice. Errors may be
present. Collaboration is welcomed.**

#### TODO:

- Tighten the definition of impurity.
- Confirm the purity of all precompiles (especially zksnarks).
- Look further into future impure opcodes.
- Add details for call-type opcodes in opcode listings
- Add references to py-evm

# Background

The need for this document has come from the requirement for the Casper FFG
contract (see
[EIP-1011](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1011.md)) to
be able to verify signature validation contracts as "pure" so an attacker
cannot cause a signature validation on a `vote()` transaction to succeed whilst
simultaneously failing on a `slash()` transaction.

This document is the result of "reverse engineering" the following two
contracts and the majority any credit attributed to this document is deserving
of their authors:

- [Serpent Purity Checker](https://github.com/ethereum/research/blob/master/impurity/check_for_impurity.se) in [ethereum/research](https://github.com/ethereum/research) by "vub". I think the author is Vitalik Buterin, but I am not sure.
- [LLL Port](https://github.com/ethereum/casper/pull/143/files) of the above
  Serpent Purity Checker by @ralexstokes.

## Definition of Impurity

A contract is considered pure if it will always return the same result given
sufficient gas for execution and the same transaction data.

_TODO: Tighten down this definition._

<h2 id="opcode-table">Impure Opcode Table</h2>

| Opcode Value | Mnemonic | Impurity Category | 
|--|--|--|
| `0x31` | [BALANCE](#BALANCE) | [Always Impure](#always-impure) |
|`0x32` | [ORIGIN](#ORIGIN) | [Always Impure](#always-impure) |
|`0x33` | [CALLER](#CALLER) | [Always Impure](#always-impure) |
|`0x3a` | [GASPRICE](#GASPRICE) | [Always Impure](#always-impure) |
|`0x3b` | [EXTCODESIZE](#EXTCODESIZE) | [Always Impure](#always-impure) |
|`0x3c` | [EXTCODECOPY](#EXTCODECOPY) | [Always Impure](#always-impure) |
|`0x40` | [BLOCKHASH](#BLOCKHASH) | [Always Impure](#always-impure) |
|`0x41` | [COINBASE](#COINBASE) | [Always Impure](#always-impure) |
|`0x42` | [TIMESTAMP](#TIMESTAMP) | [Always Impure](#always-impure) |
|`0x43` | [NUMBER](#NUMBER) | [Always Impure](#always-impure) |
|`0x44` | [DIFFICULTY](#DIFFICULTY) | [Always Impure](#always-impure) |
|`0x45` | [GASLIMIT](#GASLIMIT) | [Always Impure](#always-impure) |
|`0x46` - `0x4F` | Range of future impure opcodes | [Future Impure Opcodes](#future-impure)
|`0x54` | [SLOAD](#SLOAD) | [Always Impure](#always-impure) |
|`0x55` | [SSTORE](#SSTORE) | [Always Impure](#always-impure) |
|`0xf0` | [CREATE](#CREATE) | [Always Impure](#always-impure) |
|`0xff` | [SELFDESTRUCT](#SELFDESTRUCT) | [Always Impure](#always-impure) |
|`0xf1` | [CALL](CALL) | [Potentially Impure Call-Type](#call-type) |
|`0xf2` | [CALLCODE](CALLCODE) | [Potentially Impure Call-Type](#call-type) |
|`0xf4` | [DELEGATECALL](DELEGATECALL) | [Potentially Impure Call-Type](#call-type) |
|`0xfa` | [STATICCALL](STATICCALL) | [Potentially Impure Call-Type](#call-type) |
| &ast; `0xfb`  | [CREATE2](#CREATE) | [Always Impure](#always-impure) |

_&ast; Opcodes which were not implemented at the time of writing, but the author
has an expectation they will be implemented in the future._

## Impurity Categories

There are three classifications for impure opcodes: always impure, potentially
impure call-type and future impure opcodes. Each category is described below.

<h3 id="always-impure">Always Impure</h3>

These opcodes have no use other than to mutate state, return mutable state or
provide context about the execution environment. Any contract which includes an
"always impure" opcode should be immediately considered impure.

<h3 id="future-impure">Future Impure Opcodes</h3>

These opcodes are assumed to be reserved for future impure opcodes.  At
the time of writing, there is no formal declaration that this is the case and
this judgement is solely based off the authors informal conversations with the
Ethereum community.

<h3 id="call-type">Potentially Impure Call-Type</h3>

Call-type opcodes (see the [table](#opcode-table) for a listing)  may execute
code at some other address. It is possible for an external call to be either
pure or impure, depending on the address specified for the call. The use of a
call-type opcode can only be considered pure if the address specified is:

- An address that has already been determined to be pure.
- Any of the precompile addresses within the range of `0x0000000000000000000000000000000000000001` to `0x0000000000000000000000000000000000000008`. _Note: the purity of these contracts is yet to be confirmed._

See the [Address Detection Techniques](#address-detection) section for
some techniques for extracting the address supplied to a call-type opcode from
bytecode.

**Any call to an externally-owned (non-contract) address should be considered
impure**. This is because it can potentially have impure code deployed to it.

<h2 id="address-detection">Address Detection Techniques</h2>

Call-type opcodes (see the [table](#opcode-table) for a listing) can only be
considered pure if they call a specific set of addresses (see [Potentially
Impure Call-Types](#call-type). Therefore, in order to permit some call-type
opcodes it is necessary to determine the called address from the bytecode. This
section describes methods which may be used to find the address supplied to the
call-type opcode with certainty.

The code which may place an address on the stack for call-type opcode can be
arbitrarily complex and only discoverable by executing said code. To allow
purity checking within a single Ethereum transaction the techniques here are
simplistic and will provide false positives (indicating impurity). However,
these techniques should never produce false negatives (indicating purity).

### Convenience Functions

First two convenience functions are declared; `get_opcode(n)` and
`get_last_opcode_param(n)`.

#### Convenience Function `get_opcode(n)`

Returns the `n`'th opcode declared in the subject `bytecode[]`. 

If `n` is out of bounds of `bytecode[]` the function returns `None`.

Example:
```python
ADD = 0x01
PUSH2 = 0x61

bytecode = [PUSH2, 2, 1, ADD]
get_opcode(0)
# 3
get_opcode(2)
# None
```

#### Convenience Function `get_last_opcode_param(n)`

Returns the final parameter supplied to the `n`'th opcode declared in
the subject `bytecode[]`.

If `n` is out of bounds of `bytecode[]` or the `n`'th opcode does not have
parameters the function returns `None`.

Example:
```python
ADD = 0x01
PUSH2 = 0x61

bytecode = [PUSH2, 2, 1, ADD]
get_last_opcode_param(0)
# 1
get_last_opcode_param(1)
# None
get_last_opcode_param(2)
# None
```

### Address Detection Functions

Four functions are now declared which return an address if a specific pattern
of opcodes is found to precede a call-type opcode. If all of these functions
return `None`, then the contract should be assumed to be impure.

Each function takes an input `c` which is the index of the call-type opcode in
question.

#### Address Detection Function #1

```python
PUSH1 = 0x60
PUSH32 = 0x7f

def address_detector_1(c):
    if PUSH1 <= get_opcode(c-2) <= PUSH32:
        return get_last_opcode_param(c-2)
    else:
        return None
```

#### Address Detection Function #2

```python
SUB = 0x03
GAS = 0x5a
PUSH1 = 0x60
PUSH32 = 0x7f

def address_detector_2(c):
    if (get_opcode(c-1) == SUB and
       get_opcode(c-2) == GAS and
       PUSH1 <= get_opcode(c-3) <= PUSH32):
        return get_last_opcode_param(c-3)
    else:
        return None
```

#### Address Detection Function #3

```python
GAS = 0x5a
SWAP1 = 0x90

def address_detector_3(c):
    if (get_opcode(c-1) == GAS OR
       get_opcode(c-1) == SWAP1):
        return get_last_opcode_param(c-2)
    else:
        return None
```

#### Address Detection Function #4

```python
def address_detector_4(c):
    if (0x80 <= get_opcode(c-1) <= 0x8f):
        return get_last_opcode_param(c-2)
    else:
        return None
```

## Opcode Listing

This section contains an opcode-by-opcode listing of each defined opcode. For
each opcode the following is provided:

- **Summary**: a brief description of what the opcode does.
- **References**: a link to a resource provides extra detail on the opcode.
- **Impurity Reasoning**: some reasoning as to why the opcode could be considered
  to be impure.
- **Potential Attack**: a scenario which assumes some attacker has deployed a
  contract and wishes to be able to have some control (pre-determined or ad
hoc) of the return result of the contract. This section does not exhaustively
list potential attacks, it simply provides an example for demonstrative
purposes.

<h3 id="BALANCE">BALANCE</h3>

**Summary:** Returns the balance of some address.  
**References:** [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf).  
**Impurity Reasoning:** The balance of an address is mutable state which can
potentially be modified at any time.  
**Potential Attack:** An attacker may influence the return value of a contract
call by altering the balance of some external account.

<h3 id="ORIGIN">ORIGIN</h3>

**Summary:** Returns the address of the sender of the transaction which
triggered execution. In Solidity, this is `tx.origin`.  
**References:** [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf).  
**Impurity Reasoning:** The address derived from a transaction signature is
variable and not included in the transaction data. Therefore, it can be used to
give varying results for identical transaction data.  
**Potential Attack:** An attacker may influence the return value of a contract
call by varying the private key with which a transaction is signed.

<h3 id="CALLER">CALLER</h3>

**Summary:** Returns the address directly responsible for the execution. In
Solidity, this is `msg.sender`.  
**References:** [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf).  
**Impurity Reasoning:** A contract may return different results depending on
the caller address, allowing the selection of different results given the same
transaction data.   
**Potential Attack:** An attacker may influence the return value of a contract
call by varying the private key with which a transaction is signed or using an
intermediary contract to alter the `CALLER` value.


<h3 id="GASPRICE">GASPRICE</h3>

**Summary:** Returns the current gas price.  
**References:** [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf).  
**Impurity Reasoning:** Gas price is variable and ultimately determined by
block proposers, therefore it can be considered mutable state.  
**Potential Attack:** An attacker may influence the return value of a contract
call by using some means to alter the gas price (e.g., directly controlling
block proposers).


<h3 id="EXTCODESIZE">EXTCODESIZE</h3>

**Summary:** Returns the size of the code held at some address.  
**References:** [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf).  
**Impurity Reasoning:** Code size at an address can be increased from `0` by deploying a
contract to it.   
**Potential Attack:** An attacker may influence the return value of a contract.  
call by deploying code to some pre-computed address.


<h3 id="EXTCODECOPY">EXTCODECOPY</h3>

**Summary:** Copies some amount of code at some address to some position in
memory.  
**References:** [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf).  
**Impurity Reasoning:** The code copied to memory from an address can be varied
by deploying a contract to it.  
**Potential Attack:** An attacker may influence the return value of a contract
call by deploying code to some pre-computed address.  

<h3 id="BLOCKHASH">BLOCKHASH</h3>

**Summary:** Returns the hash of some past block (within the previous 256
complete blocks).  
**References:** [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf).  
**Impurity Reasoning:** Block hashes are ultimately determined by block proposers and
can therefore be considered mutable state.  
**Potential Attack:** An attacker may influence the return value of a contract
call by controlling some portion of block proposers and selecting block hashes based
upon how they will influence the contract call.  

<h3 id="COINBASE">COINBASE</h3>

**Summary:** Returns the beneficiary address of the block.  
**References:** [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf).  
**Impurity Reasoning:** The coinbase address is determined by block proposers
and can be considered an input variable not included in transaction
data.  
**Potential Attack:** An attacker may influence the return value of a contract
call by controlling some portion of block proposers and declaring the beneficiary
address based upon how it will influence the contract call.

<h3 id="TIMESTAMP">TIMESTAMP</h3>

**Summary:** Returns the timestamp of the block.  
**References:** [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf).  
**Impurity Reasoning:** The timestamp is determined (within a limited range) by
block proposers and can be considered an input variable not included
in transaction data.  
**Potential Attack:** An attacker may influence the return value of a contract
call by controlling some portion of block proposers and declaring the timestamp
based upon how it will influence the contract call.

<h3 id="NUMBER">NUMBER</h3>

**Summary:** Returns the number of the block (count of blocks in the chain
since genesis).  
**References:** [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf).  
**Impurity Reasoning:** Varies block-by-block and can therefore be considered
an input variable not determined in transaction data.  
**Potential Attack:** An attacker may influence the return value of a contract
call by selecting in which block a transaction should be included.

<h3 id="DIFFICULTY">DIFFICULTY</h3>

**Summary:** Returns the block difficulty.  
**References:** [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf).  
**Impurity Reasoning:** The block difficulty is ultimately determined
collectively by miners and can be considered an input variable not included in
transaction data.  
**Potential Attack:** An attacker may influence the return value of a contract
call by assuming some control of the collective hash rate and modifying it
based upon how it will influence the contract call.

<h3 id="GASLIMIT">GASLIMIT</h3>

**Summary:** Returns the block gas limit.  
**References:** [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf).  
**Impurity Reasoning:** The gas limit is ultimately determined by miners and
can be considered an input variable not included in transaction data.  
**Potential Attack:** An attacker may influence the return value of a contract
call by using some means to alter the gas limit (e.g., directly controlling
block proposers or spamming the network).

<h3 id="SLOAD">SLOAD</h3>

**Summary:** Returns a word from storage.  
**References:** [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf).  
**Impurity Reasoning:** Reads mutable state.  
**Potential Attack:** At the time of writing the author is not aware of any
attack using SLOAD if all other purity directives are followed. However,
attacks could be imagined if combined with the `SLOAD` opcodes (other
attacks may be possible).

<h3 id="SSTORE">SSTORE</h3>

**Summary:** Saves some word to storage.  
**References:** [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf).  
**Impurity Reasoning:** Mutates state.  
**Potential Attack:** At the time of writing the author is not aware of any
attack using SSTORE if all other purity directives are followed. However,
attacks could be imagined if combined with the `SSTORE` or `GAS` opcodes (other
attacks may be possible).

<h3 id="XXXX">CREATE</h3>

**Summary:** Creates a new account given some code.  
**References:** [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf).  
**Impurity Reasoning:** Mutates state.  
**Potential Attack:** At the time of writing the author is not aware of any
attack using CREATE if all other purity directives are followed. However,
attacks could be imagined if combined with the `EXTCODESIZE` opcode (other
attacks may be possible).

<h3 id="SELFDESTRUCT">SELFDESTRUCT</h3>

**Summary:** Registers the account for deletion, sending remaining Ether to
some address.  
**References:** [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf).  
**Impurity Reasoning:** Mutates state.  
**Potential Attack:** An attacker may self-destruct a contract, causing all
future calls to it to fail.  


<h3 id="CREATE2">CREATE2</h3>

_This opcode has not been implemented at the time of writing._

**Summary:** Creates a new account given some code and some nonce (as opposed
to `CREATE` which uses the current account nonce).  
**References:** [EIP86](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-86.md).  
**Impurity Reasoning:** Mutates state.  
**Potential Attack:** An attacker could craft a contract which succeeds the
first time it is called, but fails all other times.    

