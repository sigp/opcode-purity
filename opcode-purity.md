
#TODO:

Are zksnarks precompiles pure?

## Definition of Impurity

A contract is considered pure if given sufficient gas for execution and the
same `DATA` field, it will always return the same result.

<h3 id="opcode-table">Impure Opcode Table</h3>

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

<h3 id="always-impure">Future Impure Opcodes</h3>

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
- Any of the precompile addresses within the range of `0x0000000000000000000000000000000000000001` to `0x0000000000000000000000000000000000000008`.

See the [Address Detection Techniques](#address-detection) section for
some techniques for extracting the address supplied to a call-type opcode from
bytecode.

**Any call to an externally-owned (non-contract) address should be considered
impure**. This is because it can potentially have impure code deployed to it.

<h2 id="address-detection">Address Detection Techniques</h2>

Detecting the purity of some contract code is likely to be a task done via the
EVM. With this in mind, a method of extracting the address supplied to some
call-type opcode by reading the bytecode. First, we define two convenience
functions:

- `get_opcode(n)`: returns the `n`'th opcode declared in the bytecode.
- `get_last_opcode_param(n)`: returns the final parameter supplied to
  the `n`th opcode declared in the bytecode. E.g., assume that `bytecode[]` is
an array of 256 bit words and that `bytecode[0]` is PUSH2. In such a case
`get_last_opcode_param[0]` would return `bytecode[2]`.

If either of these functions attempt to access an invalid index of the bytecode
they turn `None`.

Now we declare five functions using pseudo-code which can be used to return an
address. If all of these functions return `None` the contract should be
considered impure as we were unable to ascertain with the address
supplied to the call-type opcode. Each function takes an input `c` which is the
index of the call-type opcode in the bytecode (i.e., the parameter that would need to be
supplied to `get_opcode()` to return the call-type opcode).

### Address Detection Function #1

```python
def address_detector_1(c) -> address:
    if 0x60 <= get_opcode(n-2) <= 0x7f:
        return get_last_opcode_param(n-2)
    else:
        return None
```

### Address Detection Function #2

```python
def address_detector_2(c) -> address:
    if (get_opcode(n-1) == 0x03 and
        get_opcode(n-2) == 0x5a and
        0x60 <= get_opcode(n-3) <= 0x7f):
        return get_last_opcode_param(n-3)
    else:
        return None
```

### Address Detection Function #3

**NOTE: I am almost certain this method is invalid, but it exists in the
current version of the purity checker. Do not implement this method.**

```python
def address_detector_3(c) -> address:
    if get_opcode(n-1) == 0x5a:
        return get_last_opcode_param(n-2)
    else:
        return None
```

### Address Detection Function #4

```python
def address_detector_4(c) -> address:
    if get_opcode(n-1) == 0x90:
        return get_last_opcode_param(n-2)
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

_This opcode has not been implemented at this time of writing._

**Summary:** Creates a new account given some code and some nonce (as opposed
to `CREATE` which uses the current account nonce).  
**References:** [EIP86](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-86.md).  
**Impurity Reasoning:** XXXX.  
**Potential Attack:** An attacker could craft a contract which succeeds the
first time it is called, but fails all other times.    

