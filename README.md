# Context

This repository is the basis for the blog post found here: https://blog.sigmaprime.io/solidity-security.html. 

It forms the basis of the Smart Contract Security section in the Mastering Ethereum book: https://github.com/ethereumbook/ethereumbook

# Summary

This post aims to be a relatively in-depth and up-to-date introductory post detailing the past mistakes that have been made by Solidity developers in an effort to prevent future devs from repeating history.

Although in its infancy, Solidity has had widespread adoption and is used to compile the byte-code in many Ethereum smart contracts we see today. There have been a number of harsh lessons learnt by developers and users alike in discovering the nuances of the language and the EVM. This post aims to be a relatively in-depth and up-to-date introductory post detailing the past mistakes that have been made by Solidity developers in an effort to prevent future devs from repeating history.

*As this is a rapidly changing area, I've put this post on [Github](https://github.com/sigp/solidity-security-blog) to encourage anyone/everyone to contribute to this post or submit issues for the errors that I've surely made.*

# Table of Contents

#### [1. Re-Entrancy](#reentrancy)
 * [The Vulnerability](#re-vuln)
 * [Preventative Techniques](#re-prev)
 * [Real-World Example: The DAO](#re-example)

#### [2. Arithmetic Over/Under Flows](#ouflow)
 * [The Vulnerability](#ou-vuln)
 * [Preventative Techniques](#ou-prev)
 * [Real-World Examples: PoWHC and Batch Transfer Overflow (CVE-2018-10299)](#ou-example)

#### [3. Unexpected Ether](#ether)
 * [The Vulnerability](#ether-vuln)
 * [Preventative Techniques](#ether-prev)
 * [Real-World Examples: Unknown](#ether-example)

#### [4. Delegatecall](#delegatecall)
 * [The Vulnerability](#dc-vuln)
 * [Preventative Techniques](#dc-prev)
 * [Real-World Examples: Parity Multisig Wallet (Second Hack)](#dc-example)

#### [5. Default Visibilities](#visibility)
 * [The Vulnerability](#visibility-vuln)
 * [Preventative Techniques](#visibility-prev)
 * [Real-World Example: Parity MultiSig Wallet (First Hack)](#visibility-example)

#### [6. Entropy Illusion](#entropy)
 * [The Vulnerability](#entropy-vuln)
 * [Preventative Techniques](#entropy-prev)
 * [Real-World Example: PRNG Contracts](#entropy-example)

#### [7. External Contract Referencing](#contract-reference)
 * [The Vulnerability](#cr-vuln)
 * [Preventative Techniques](#cr-prev)
 * [Real-World Example: Re-Entrancy Honey Pot](#cr-example)

#### [8. Short Address/Parameter Attack](#short-address)
 * [The Vulnerability](#short-vuln)
 * [Preventative Techniques](#short-prev)
 * [Real-World Example: Unknown](#short-example)

#### [9. Unchecked CALL Return Values](#unchecked-calls)
 * [The Vulnerability](#unchecked-calls-vuln)
 * [Preventative Techniques](#unchecked-calls-prev)
 * [Real-World Examples: Etherpot and King of the Ether](#unchecked-calls-example)

#### [10. Race Conditions / Front Running](#race-conditions)
 * [The Vulnerability](#race-conditions-vuln)
 * [Preventative Techniques](#race-conditions-prev)
 * [Real-World Examples: ERC20 and Bancor](#race-conditions-example)

#### [11. Denial Of Service (DOS)](#dos)
 * [The Vulnerability](#dos-vuln)
 * [Preventative Techniques](#dos-prev)
 * [Real-World Example: GovernMental](#dos-example)

#### [12. Block Timestamp Manipulation](#block-timestamp)
 * [The Vulnerability](#block-timestamp-vuln)
 * [Preventative Techniques](#block-timestamp-prev)
 * [Real-World Example: GovernMental](#block-timestamp-example)

#### [13. Constructors with Care](#constructors)
 * [The Vulnerability](#constructors-vuln)
 * [Preventative Techniques](#constructors-prev)
 * [Real-World Example: Rubixi](#constructors-example)

#### [14. Uninitialised Storage Pointers](#storage)
 * [The Vulnerability](#storage-vuln)
 * [Preventative Techniques](#storage-prev)
 * [Real-World Examples: Honey Pots: OpenAddressLottery and CryptoRoulette](#storage-example)

#### [15. Floating Points and Numerical Precision](#precision)
 * [The Vulnerability](#precision-vuln)
 * [Preventative Techniques](#precision-prev)
 * [Real-World Example: Ethstick](#precision-example)

#### [16. tx.origin Authentication](#tx-origin)
 * [The Vulnerability](#tx-origin-vuln)
 * [Preventative Techniques](#tx-origin-prev)
 * [Real-World Example: Unknown](#tx-origin-example)

## [Ethereum Quirks](#ethereum-quirks)
* [Keyless Ether](#keyless-eth)
* [One Time Addresses](#one-time-addresses)
* [Single Transaction Airdrops](#single-transaction-airdrops)

## [List of Interesting Crypto Related Hacks/Bugs](#hacks)


## References / Further Reading List

- [Ethereum Wiki - Safety](https://github.com/ethereum/wiki/wiki/Safety)
- [Solidity Docs - Security Considerations](solidity.readthedocs.io/en/latest/security-considerations.html)
- [Consensus - Ethereum Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices)
- [History of Ethereum Security Vulnerabilities, Hacks and Their Fixes](https://applicature.com/blog/history-of-ethereum-security-vulnerabilities-hacks-and-their-fixes)
- [Decentralized Application Security Project (DASP) Top 10 of 2018](http://www.dasp.co/)
- [A Survey of attacks on Ethereum Smart Contracts](https://eprint.iacr.org/2016/1007.pdf)
- [Ethereum Smart Contract Security](https://medium.com/cryptronics/ethereum-smart-contract-security-73b0ede73fa8)
- [Lessons Learnt from the Underhanded Solidity Contest](https://medium.com/@chriseth/lessons-learnt-from-the-underhanded-solidity-contest-8388960e09b1)

<h2 id="reentrancy"><span id="SP-1">1. Re-Entrancy</span></h2>

One of the features of Ethereum smart contracts is the ability to call and utilise code of other external contracts. Contracts also typically handle ether, and as such often send ether to various external user addresses. The operation of calling external contracts, or sending ether to an address, requires the contract to submit an external call. These external calls can be hijacked by attackers whereby they force the contract to execute further code (i.e. through a fallback function) , including calls back into itself. Thus the code execution "*re-enters*" the contract. Attacks of this kind were used in the infamous DAO hack.

For further reading on re-entrancy attacks, see [Reentrancy Attack On Smart Contracts](https://medium.com/@gus_tavo_guim/reentrancy-attack-on-smart-contracts-how-to-identify-the-exploitable-and-an-example-of-an-attack-4470a2d8dfe4) and [Consensus - Ethereum Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/known_attacks/#reentrancy).

<h3 id="re-vuln">The Vulnerability</h3>

This attack can occur when a contract sends ether to an unknown address. An attacker can carefully construct a contract at an external address which contains malicious code in the [fallback function](https://solidity.readthedocs.io/en/latest/contracts.html?highlight=fallback#fallback-function). Thus, when a contract sends ether to this address, it will invoke the malicious code. Typically the malicious code executes a function on the vulnerable contract, performing operations not expected by the developer. The name "re-entrancy" comes from the fact that the external malicious contract calls back a function on the vulnerable contract and "*re-enters*" code execution at an arbitrary location on the vulnerable contract.

To clarify this, consider the simple vulnerable contract, which acts as an Ethereum vault that allows depositors to only withdraw 1 ether per week.

EtherStore.sol:
```solidity
contract EtherStore {

    uint256 public withdrawalLimit = 1 ether;
    mapping(address => uint256) public lastWithdrawTime;
    mapping(address => uint256) public balances;

    function depositFunds() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdrawFunds (uint256 _weiToWithdraw) public {
        require(balances[msg.sender] >= _weiToWithdraw);
        // limit the withdrawal
        require(_weiToWithdraw <= withdrawalLimit);
        // limit the time allowed to withdraw
        require(now >= lastWithdrawTime[msg.sender] + 1 weeks);
        require(msg.sender.call.value(_weiToWithdraw)());
        balances[msg.sender] -= _weiToWithdraw;
        lastWithdrawTime[msg.sender] = now;
    }
 }
```

This contract has two public functions. `depositFunds()` and `withdrawFunds()`. The `depositFunds()` function simply increments the senders balances. The `withdrawFunds()` function allows the sender to specify the amount of wei to withdraw. It will only succeed if the requested amount to withdraw is less than 1 ether and a withdrawal hasn't occurred in the last week. Or does it?...

The vulnerability comes on line \[17\] where we send the user their requested amount of ether. Consider a malicious attacker creating the following contract,

Attack.sol:
```solidity
import "EtherStore.sol";

contract Attack {
  EtherStore public etherStore;

  // initialise the etherStore variable with the contract address
  constructor(address _etherStoreAddress) {
      etherStore = EtherStore(_etherStoreAddress);
  }

  function pwnEtherStore() public payable {
      // attack to the nearest ether
      require(msg.value >= 1 ether);
      // send eth to the depositFunds() function
      etherStore.depositFunds.value(1 ether)();
      // start the magic
      etherStore.withdrawFunds(1 ether);
  }

  function collectEther() public {
      msg.sender.transfer(this.balance);
  }

  // fallback function - where the magic happens
  function () payable {
      if (etherStore.balance > 1 ether) {
          etherStore.withdrawFunds(1 ether);
      }
  }
}
```

Let us see how this malicious contract can exploit our `EtherStore` contract. The attacker would create the above contract (let's say at the address `0x0...123`) with the `EtherStore`'s contract address as the constructor parameter. This will initialize and point the public variable `etherStore` to the contract we wish to attack.

The attacker would then call the `pwnEtherStore()` function, with some amount of ether (greater than or equal to 1), let's say `1 ether` for this example. In this example we assume a number of other users have deposited ether into this contract, such that it's current balance is `10 ether`. The following would then occur:

1. **Attack.sol - Line \[15\]** - The `depositFunds()` function of the EtherStore contract will be called with a `msg.value` of `1 ether` (and a lot of gas). The sender (`msg.sender`) will be our malicious contract (`0x0...123`). Thus, `balances[0x0..123] = 1 ether`.

2. **Attack.sol - Line \[17\]** - The malicious contract will then call the `withdrawFunds()` function of the `EtherStore` contract with a parameter of `1 ether`. This will pass all the requirements (Lines \[12\]-\[16\] of the `EtherStore` contract) as we have made no previous withdrawals.

3. **EtherStore.sol - Line \[17\]** - The contract will then send `1 ether` back to the malicious contract.

4. **Attack.sol - Line \[25\]** - The ether sent to the malicious contract will then execute the fallback function.

5. **Attack.sol - Line \[26\]** - The total balance of the EtherStore contract was `10 ether` and is now `9 ether` so this if statement passes.

6. **Attack.sol - Line \[27\]** - The fallback function then calls the `EtherStore` `withdrawFunds()` function again and "*re-enters*" the `EtherStore` contract.

7. **EtherStore.sol - Line \[11\]** - In this second call to `withdrawFunds()`, our balance is still `1 ether` as line \[18\] has not yet been executed. Thus, we still have `balances[0x0..123] = 1 ether`. This is also the case for the `lastWithdrawTime` variable. Again, we pass all the requirements.

8. **EtherStore.sol - Line \[17\]** - We withdraw another `1 ether`.

9. **Steps 4-8 will repeat** -  until `EtherStore.balance >= 1` as dictated by line \[26\] in `Attack.sol`.

10. **Attack.sol - Line \[26\]** - Once there less 1 (or less) ether left in the `EtherStore` contract, this if statement will fail. This will then allow lines \[18\] and \[19\] of the `EtherStore` contract to be executed (for each call to the `withdrawFunds()` function).

11. **EtherStore.sol - Lines \[18\] and \[19\]** - The `balances` and `lastWithdrawTime` mappings will be set and the execution will end.

The final result, is that the attacker has withdrawn all (bar 1) ether from the `EtherStore` contract, instantaneously with a single transaction.

<h3 id="re-prevention">Preventative Techniques</h3>

There are a number of common techniques which help avoid potential re-entrancy vulnerabilities in smart contracts. The first is to ( whenever possible) use the built-in [transfer()](http://solidity.readthedocs.io/en/latest/units-and-global-variables.html#address-related) function when sending ether to external contracts. The transfer function only sends `2300 gas` with the external call, which isn't enough for the destination address/contract to call another contract (i.e. re-enter the sending contract).

The second technique is to ensure that all logic that changes state variables happen before ether is sent out of the contract (or any external call). In the `EtherStore` example, lines \[18\] and \[19\] of `EtherStore.sol` should be put before line \[17\]. It is good practice to place any code that performs external calls to unknown addresses as the last operation in a localised function or piece of code execution. This is known as the [checks-effects-interactions](http://solidity.readthedocs.io/en/latest/security-considerations.html#use-the-checks-effects-interactions-pattern) pattern.

A third technique is to introduce a mutex. That is, to add a state variable which locks the contract during code execution, preventing reentrancy calls.

Applying all of these techniques (all three are unnecessary, but is done for demonstrative purposes) to `EtherStore.sol`, gives the re-entrancy-free contract:
```solidity
contract EtherStore {

    // initialise the mutex
    bool reEntrancyMutex = false;
    uint256 public withdrawalLimit = 1 ether;
    mapping(address => uint256) public lastWithdrawTime;
    mapping(address => uint256) public balances;

    function depositFunds() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdrawFunds (uint256 _weiToWithdraw) public {
        require(!reEntrancyMutex);
        require(balances[msg.sender] >= _weiToWithdraw);
        // limit the withdrawal
        require(_weiToWithdraw <= withdrawalLimit);
        // limit the time allowed to withdraw
        require(now >= lastWithdrawTime[msg.sender] + 1 weeks);
        balances[msg.sender] -= _weiToWithdraw;
        lastWithdrawTime[msg.sender] = now;
        // set the reEntrancy mutex before the external call
        reEntrancyMutex = true;
        msg.sender.transfer(_weiToWithdraw);
        // release the mutex after the external call
        reEntrancyMutex = false;
    }
 }
```

<h3 id="re-example">Real-World Example: The DAO</h3>

[The DAO](https://en.wikipedia.org/wiki/The_DAO_(organization)) (Decentralized Autonomous Organization) was one of the major hacks that occurred in the early development of Ethereum. At the time, the contract held over $150 million USD. Re-entrancy played a major role in the attack which ultimately lead to the hard-fork that created Ethereum Classic (ETC). For a good analysis of the DAO exploit, see [Phil Daian's post](http://hackingdistributed.com/2016/06/18/analysis-of-the-dao-exploit/).

<h2 id="ouflow"><span id="SP-2">2. Arithmetic Over/Under Flows</span></h2>

The Ethereum Virtual Machine (EVM) specifies fixed-size data types for integers. This means that an integer variable, only has a certain range of numbers it can represent. A `uint8` for example, can only store numbers in the range \[0,255\]. Trying to store `256` into a `uint8` will result in `0`. If care is not taken, variables in Solidity can be exploited if user input is unchecked and calculations are performed which result in numbers that lie outside the range of the data type that stores them.

For further reading on arithmetic over/under flows, see [How to Secure Your Smart Contracts](https://medium.com/loom-network/how-to-secure-your-smart-contracts-6-solidity-vulnerabilities-and-how-to-avoid-them-part-1-c33048d4d17d), [Ethereum Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/known_attacks/#integer-overflow-and-underflow) and [Ethereum, Solidity and integer overflows: programming blockchains like 1970](https://randomoracle.wordpress.com/2018/04/27/ethereum-solidity-and-integer-overflows-programming-blockchains-like-1970/)

<h3 id="ou-vuln">The Vulnerability</h3>

An over/under flow occurs when an operation is performed that requires a fixed size variable to store a number (or piece of data) that is outside the range of the variable's data type.

For example, subtracting `1` from a `uint8` (unsigned integer of 8 bits, i.e. only positive) variable that stores `0` as it's value, will result in the number `255`. This is an underflow. We have assigned a number below the range of the `uint8`, the result *wraps around* and gives the largest number a `uint8` can store. Similarly, adding `2^8=256` to a `uint8` will leave the variable unchanged as we have wrapped around the entire length of the `uint` (for the mathematicians, this is similar to adding $2\pi$ to the angle of a trigonometric function, $\sin(x) = \sin(x+2\pi)$). Adding numbers larger than the data type's range is called an overflow. For clarity, adding `257` to a `uint8` that currently has a zero value will result in the number `1`. It's sometimes instructive to think of fixed type variables being cyclic, where we start again from zero  if we add numbers above the largest possible stored number, and vice-versa for zero (where we start counting down from the largest number the more we subtract from 0).

These kinds of numerical caveats allow attackers to misuse code and create unexpected logic flows. For example, consider the time locking contract below.

TimeLock.sol:
```solidity
contract TimeLock {

    mapping(address => uint) public balances;
    mapping(address => uint) public lockTime;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
        lockTime[msg.sender] = now + 1 weeks;
    }

    function increaseLockTime(uint _secondsToIncrease) public {
        lockTime[msg.sender] += _secondsToIncrease;
    }

    function withdraw() public {
        require(balances[msg.sender] > 0);
        require(now > lockTime[msg.sender]);
        uint transferValue = balances[msg.sender];
        balances[msg.sender] = 0;
        msg.sender.transfer(transferValue);
    }
}
```

This contract is designed to act like a time vault, where users can deposit ether into the contract and it will be locked there for at least a week. The user may extend the wait time to longer than 1 week if they choose, but once deposited, the user can be sure their ether is locked in safely for at least a week. Or can they?...

In the event a user is forced to hand over their private key (think hostage situation) a contract such as this may be handy to ensure ether is unobtainable in short periods of time. If a user had locked in `100 ether` in this contract and handed their keys over to an attacker, an attacker could use an overflow to receive the ether, regardless of the `lockTime`.

The attacker could determine the current `lockTime` for the address they now hold the key for (its a public variable). Let's call this `userLockTime`. They could then call the `increaseLockTime` function and pass as an argument the number `2^256 - userLockTime`. This number  would be added to the current `userLockTime` and cause an overflow, resetting `lockTime[msg.sender]` to `0`. The attacker could then simply call the `withdraw` function to obtain their reward.

Let's look at another example, this one from the [Ethernaut Challanges](https://github.com/OpenZeppelin/ethernaut).

**SPOILER ALERT:** *If you've not yet done the Ethernaut challenges, this gives a solution to one of the levels*.

```solidity
pragma solidity ^0.4.18;

contract Token {

  mapping(address => uint) balances;
  uint public totalSupply;

  function Token(uint _initialSupply) {
    balances[msg.sender] = totalSupply = _initialSupply;
  }

  function transfer(address _to, uint _value) public returns (bool) {
    require(balances[msg.sender] - _value >= 0);
    balances[msg.sender] -= _value;
    balances[_to] += _value;
    return true;
  }

  function balanceOf(address _owner) public constant returns (uint balance) {
    return balances[_owner];
  }
}
```

This is a simple token contract which employs a `transfer()` function, allowing participants to move their tokens around. Can you see the error in this contract?

The flaw comes in the `transfer()` function. The require statement on line \[13\] can be bypassed using an underflow. Consider a user that has no balance. They could call the `transfer()` function with any non-zero `_value` and pass the require statement on line \[13\]. This is because `balances[msg.sender]` is zero (and a `uint256`) so subtracting any positive amount (excluding `2^256`) will result in a positive number due to the underflow we described above. This is also true for line \[14\], where our balance will be credited with a positive number. Thus, in this example, we have achieved free tokens due to an underflow vulnerability.

<h3 id="ou-prevention">Preventative Techniques</h3>

The (currently) conventional technique to guard against under/overflow vulnerabilities is to use or build mathematical libraries which replace the standard math operators; addition, subtraction and multiplication (division is excluded as it doesn't cause over/under flows and the EVM reverts on division by 0).

[OppenZepplin](https://github.com/OpenZeppelin/zeppelin-solidity) have done a great job in building and auditing secure libraries which can be leveraged by the Ethereum community. In particular, their [Safe Math Library](https://github.com/OpenZeppelin/zeppelin-solidity/blob/master/contracts/math/SafeMath.sol) is a reference or library to use to avoid under/over flow vulnerabilities.

To demonstrate how these libraries are used in Solidity, let us correct the `TimeLock` contract, using Open Zepplin's `SafeMath` library. The over flow-free contract would become:

```solidity
library SafeMath {

  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

contract TimeLock {
    using SafeMath for uint; // use the library for uint type
    mapping(address => uint256) public balances;
    mapping(address => uint256) public lockTime;

    function deposit() public payable {
        balances[msg.sender] = balances[msg.sender].add(msg.value);
        lockTime[msg.sender] = now.add(1 weeks);
    }

    function increaseLockTime(uint256 _secondsToIncrease) public {
        lockTime[msg.sender] = lockTime[msg.sender].add(_secondsToIncrease);
    }

    function withdraw() public {
        require(balances[msg.sender] > 0);
        require(now > lockTime[msg.sender]);
        uint transferValue = balances[msg.sender];
        balances[msg.sender] = 0;
        msg.sender.transfer(transferValue);
    }
}
```

Notice that all standard math operations have been replaced by the those defined in the `SafeMath` library. The `TimeLock` contract no longer performs any operation which is capable of doing an under/over flow.

<h3 id="ou-example">Real-World Examples: PoWHC and Batch Transfer Overflow (<a href="https://nvd.nist.gov/vuln/detail/CVE-2018-10299">CVE-2018–10299</a>)</h3>

A 4chan group decided it was a great idea to build a ponzi scheme on Ethereum, written in Solidity. They called it the Proof of Weak Hands Coin (PoWHC). Unfortunately it seems that the author(s) of the contract hadn't seen over/under flows before and consequently, 866 ether was liberated from its contract. A good overview of how the underflow occurs (which is not too dissimilar to the Ethernaut challenge above) is given in [Eric Banisadar's post](https://blog.goodaudience.com/how-800k-evaporated-from-the-powh-coin-ponzi-scheme-overnight-1b025c33b530).

Some developers also implemented a `batchTransfer()` function into some [ERC20](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md) token contracts. The implementation contained an overflow. [This post](https://medium.com/@peckshield/alert-new-batchoverflow-bug-in-multiple-erc20-smart-contracts-cve-2018-10299-511067db6536) explains it, however I think the title is misleading, in that it has nothing to do with the ERC20 standard, rather some ERC20 token contracts have a vulnerable `batchTransfer()` function implemented.

<h2 id="ether"><span id="SP-3">3. Unexpected Ether</span></h2>

Typically when ether is sent to a contract, it must execute either the fallback function, or another function described in the contract. There are two exceptions to this, where ether can exist in a contract without having executed any code. Contracts which rely on code execution for every ether sent to the contract can be vulnerable to attacks where ether is forcibly sent to a contract.

For further reading on this, see [How to Secure Your Smart Contracts: 6](https://medium.com/loom-network/how-to-secure-your-smart-contracts-6-solidity-vulnerabilities-and-how-to-avoid-them-part-2-730db0aa4834) and [ Solidity security patterns - forcing ether to a contract ](http://danielszego.blogspot.com.au/2018/03/solidity-security-patterns-forcing.html).

<h3 id="ether-vuln">The Vulnerability</h3>

A common defensive programming technique that is useful in enforcing correct state transitions or validating operations is *invariant-checking*. This technique involves defining a set of invariants (metrics or parameters that should not change) and checking these invariants remain unchanged after a single (or many) operation(s). This is typically good design, provided the invariants being checked are in fact invariants. One example of an invariant is the `totalSupply` of a fixed issuance [ERC20](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md) token. As no functions should modify this invariant, one could add a check to the `transfer()` function that ensures the `totalSupply` remains unmodified to ensure the function is working as expected.

In particular, there is one apparent *invariant*, that may be tempting to use
but can in fact be manipulated by external users (regardless of the rules put
in place in the smart contract) .This is the current ether stored in the
contract. Often when developers first learn Solidity they have the
misconception that a contract can only accept or obtain ether via payable
functions. This misconception can lead to  contracts that have false
assumptions about the ether balance within them which can lead to a range of
vulnerabilities. The smoking gun for this vulnerability is the (incorrect) use
of `this.balance`. As we will see, incorrect uses of `this.balance` can lead to
serious vulnerabilities of this type.

There are two ways in which ether can (forcibly) be sent to a contract without using a `payable` function or executing any code on the contract. These are listed below.

#### Self Destruct / Suicide

Any contract is able to implement the [`selfdestruct(address)`](http://solidity.readthedocs.io/en/latest/introduction-to-smart-contracts.html#self-destruct) function, which removes all bytecode from the contract address and sends all ether stored there to the parameter-specified address. If this specified address is also a contract, no functions (including the fallback) get called. Therefore, the `selfdestruct()` function can be used to forcibly send ether to any contract regardless of any code that may exist in the contract. This is inclusive of contracts without any payable functions. This means, any attacker can create a contract with a `selfdestruct()` function, send ether to it, call `selfdestruct(target)` and force ether to be sent to a `target` contract. Martin Swende has an excellent [blog post](http://martin.swende.se/blog/Ethereum_quirks_and_vulns.html) describing some quirks of the self-destruct opcode (Quirk #2) along with a description of how client nodes were checking incorrect invariants which could have lead to a rather catastrophic nuking of clients.

#### Pre-sent Ether

The second way a contract can obtain ether without using a `selfdestruct()` function or calling any payable functions is to pre-load the contract address with ether. Contract addresses are deterministic, in fact the address is calculated from the keccak256 (sometimes synonomous with SHA3) hash of the address creating the contract and the transaction nonce which creates the contract. Specifically, it is of the form: `address = sha3(rlp.encode([account_address,transaction_nonce]))` (see [Keyless Ether](#keyless-eth) for some fun use cases of this). This means, anyone can calculate what a contract address will be before it is created and thus send ether to that address. When the contract does get created it will have a non-zero ether balance.

Let's explore some pitfalls that can arise given the above knowledge.

Consider the overly-simple contract,

EtherGame.sol:
```solidity
contract EtherGame {

    uint public payoutMileStone1 = 3 ether;
    uint public mileStone1Reward = 2 ether;
    uint public payoutMileStone2 = 5 ether;
    uint public mileStone2Reward = 3 ether;
    uint public finalMileStone = 10 ether;
    uint public finalReward = 5 ether;

    mapping(address => uint) redeemableEther;
    // users pay 0.5 ether. At specific milestones, credit their accounts
    function play() public payable {
        require(msg.value == 0.5 ether); // each play is 0.5 ether
        uint currentBalance = this.balance + msg.value;
        // ensure no players after the game as finished
        require(currentBalance <= finalMileStone);
        // if at a milestone credit the players account
        if (currentBalance == payoutMileStone1) {
            redeemableEther[msg.sender] += mileStone1Reward;
        }
        else if (currentBalance == payoutMileStone2) {
            redeemableEther[msg.sender] += mileStone2Reward;
        }
        else if (currentBalance == finalMileStone ) {
            redeemableEther[msg.sender] += finalReward;
        }
        return;
    }

    function claimReward() public {
        // ensure the game is complete
        require(this.balance == finalMileStone);
        // ensure there is a reward to give
        require(redeemableEther[msg.sender] > 0);
        uint transferValue = redeemableEther[msg.sender];
        redeemableEther[msg.sender] = 0;
        msg.sender.transfer(transferValue);
    }
 }
```

This contract represents a simple game (which would naturally invoke [race-conditions](#race-conditions)) whereby players send `0.5 ether` quanta to the contract in hope to be the player that reaches one of three milestones first. Milestone's are denominated in ether. The first to reach the milestone may claim a portion of the ether when the game has ended. The game ends when the final milestone (`10 ether`) is reached and users can claim their rewards.

The issues with the `EtherGame` contract come from the poor use of `this.balance` in both lines \[14\] (and by association \[16\]) and \[32\]. A mischievous attacker could forcibly send a small amount of ether, let's say `0.1 ether` via the `selfdestruct()` function (discussed above) to prevent any future players from reaching a milestone. As all legitimate players can only send `0.5 ether` increments, `this.balance` would no longer be half integer numbers, as it would also have the `0.1 ether` contribution. This prevents all the if conditions on lines \[18\], \[21\] and \[24\] from being true.

Even worse, a vengeful attacker who missed a milestone, could forcibly send `10 ether` (or an equivalent amount of ether that pushes the contract's balance above the `finalMileStone`) which would lock all rewards in the contract forever. This is because the `claimReward()` function will always revert, due to the require on line \[32\] (i.e. `this.balance` is greater than `finalMileStone`).

<h3 id="ether-prevention">Preventative Techniques</h3>

This vulnerability typically arises from the misuse of `this.balance`. Contract logic, when possible, should avoid being dependent on exact values of the balance of the contract because it can be artificially manipulated. If applying logic based on `this.balance`, ensure to account for unexpected balances.

If exact values of deposited ether are required, a self-defined variable should be used that gets incremented in payable functions, to safely track the deposited ether. This variable will not be influenced by the forced ether sent via a `selfdestruct()` call.

With this in mind, a corrected version of the `EtherGame` contract could look like:
```solidity
contract EtherGame {

    uint public payoutMileStone1 = 3 ether;
    uint public mileStone1Reward = 2 ether;
    uint public payoutMileStone2 = 5 ether;
    uint public mileStone2Reward = 3 ether;
    uint public finalMileStone = 10 ether;
    uint public finalReward = 5 ether;
    uint public depositedWei;

    mapping (address => uint) redeemableEther;

    function play() public payable {
        require(msg.value == 0.5 ether);
        uint currentBalance = depositedWei + msg.value;
        // ensure no players after the game as finished
        require(currentBalance <= finalMileStone);
        if (currentBalance == payoutMileStone1) {
            redeemableEther[msg.sender] += mileStone1Reward;
        }
        else if (currentBalance == payoutMileStone2) {
            redeemableEther[msg.sender] += mileStone2Reward;
        }
        else if (currentBalance == finalMileStone ) {
            redeemableEther[msg.sender] += finalReward;
        }
        depositedWei += msg.value;
        return;
    }

    function claimReward() public {
        // ensure the game is complete
        require(depositedWei == finalMileStone);
        // ensure there is a reward to give
        require(redeemableEther[msg.sender] > 0);
        uint transferValue = redeemableEther[msg.sender];
        redeemableEther[msg.sender] = 0;
        msg.sender.transfer(transferValue);
    }
 }
```
Here, we have just created a new variable, `depositedWei` which keeps track of the known ether deposited, and it is this variable to which we perform our requirements and tests. Notice, that we no longer have any reference to `this.balance`.

<h3 id="ether-example">Real-World Example: Unknown </h3>

I'm yet to find an example of this that has been exploited in the wild. However, a few examples of exploitable contracts were given in the [Underhanded Solidity Contest](https://github.com/Arachnid/uscc/tree/master/submissions-2017/).

<h2 id="delegatecall"><span id="SP-4">4. Delegatecall</span></h2>

The `CALL` and `DELEGATECALL` opcodes are useful in allowing Ethereum developers to modularise their code. Standard external message calls to contracts are handled by the `CALL` opcode whereby code is run in the context of the external contract/function. The `DELEGATECALL` opcode is identical to the standard message call, except that the code executed at the targeted address is run in the context of the calling contract along with the fact that `msg.sender` and `msg.value` remain unchanged. This feature enables the implementation of *libraries* whereby developers can create reusable code for future contracts.

Although the differences between these two opcodes are simple and intuitive, the use of `DELEGATECALL` can lead to unexpected code execution.

For further reading, see [Ethereum Stack Exchange Question](https://ethereum.stackexchange.com/questions/3667/difference-between-call-callcode-and-delegatecall), [Solidity Docs](http://solidity.readthedocs.io/en/latest/introduction-to-smart-contracts.html#delegatecall-callcode-and-libraries) and [How to Secure Your Smart Contracts: 6](https://medium.com/loom-network/how-to-secure-your-smart-contracts-6-solidity-vulnerabilities-and-how-to-avoid-them-part-1-c33048d4d17d).

<h3 id="dc-vuln">The Vulnerability</h3>

The context preserving nature of `DELEGATECALL` has proved that building vulnerability-free custom libraries is not as easy as one might think. The code in libraries themselves can be secure and vulnerability-free however when run in the context of another application new vulnerabilities can arise. Let's see a fairly complex example of this, using Fibonacci numbers.

Consider the following library which can generate the Fibonacci sequence and sequences of similar form.
`FibonacciLib.sol`[^1]
```solidity
// library contract - calculates fibonacci-like numbers;
contract FibonacciLib {
    // initializing the standard fibonacci sequence;
    uint public start;
    uint public calculatedFibNumber;

    // modify the zeroth number in the sequence
    function setStart(uint _start) public {
        start = _start;
    }

    function setFibonacci(uint n) public {
        calculatedFibNumber = fibonacci(n);
    }

    function fibonacci(uint n) internal returns (uint) {
        if (n == 0) return start;
        else if (n == 1) return start + 1;
        else return fibonacci(n - 1) + fibonacci(n - 2);
    }
}
```
This library provides a function which can generate the *n*-th Fibonacci number in the sequence. It allows users to change the starting number of the sequence (`start`) and calculate the *n*-th Fibonacci-like numbers in this new sequence.

Let's now consider a contract that utilises this library.


`FibonacciBalance.sol`:
```solidity
contract FibonacciBalance {

    address public fibonacciLibrary;
    // the current fibonacci number to withdraw
    uint public calculatedFibNumber;
    // the starting fibonacci sequence number
    uint public start = 3;
    uint public withdrawalCounter;
    // the fibonancci function selector
    bytes4 constant fibSig = bytes4(sha3("setFibonacci(uint256)"));

    // constructor - loads the contract with ether
    constructor(address _fibonacciLibrary) public payable {
        fibonacciLibrary = _fibonacciLibrary;
    }

    function withdraw() {
        withdrawalCounter += 1;
        // calculate the fibonacci number for the current withdrawal user
        // this sets calculatedFibNumber
        require(fibonacciLibrary.delegatecall(fibSig, withdrawalCounter));
        msg.sender.transfer(calculatedFibNumber * 1 ether);
    }

    // allow users to call fibonacci library functions
    function() public {
        require(fibonacciLibrary.delegatecall(msg.data));
    }
}

```
This contract allows a participant to withdraw ether from the contract, with the amount of ether being equal to the Fibonacci number corresponding to the participants withdrawal order; i.e., the first participant gets 1 ether, the second also gets 1, the third gets 2, the forth gets 3, the fifth 5 and so on (until the balance of the contract is less than the Fibonacci number being withdrawn).

There are a number of elements in this contract that may require some explanation. Firstly, there is an interesting-looking variable, `fibSig`. This holds the first 4 bytes of the Keccak (SHA-3) hash of the string "setFibonacci(uint256)". This is known as the [function selector](https://solidity.readthedocs.io/en/latest/abi-spec.html#function-selector) and is put into `calldata` to specify which function of a smart contract will be called. It is used in the `delegatecall` function on line \[21\] to specify that we wish to run the `setFibonacci(uint256)` function. The second argument in `delegatecall` is the parameter we are passing to the function. Secondly, we assume that the address for the `FibonacciLib` library is correctly referenced in the constructor (section [External Contract Referencing](#contract-reference) discuss some potential vulnerabilities relating to this kind of contract reference initialisation).

Can you spot any error(s) in this contract? If you put this into remix, fill it with ether and call `withdraw()`, it will likely revert.

You may have noticed that the state variable `start` is used in both the library and the main calling contract. In the library contract, `start` is used to  specify the beginning of the Fibonacci sequence and is set to `0`, whereas it is set to `3` in the `FibonacciBalance` contract. You may also have noticed that the fallback function in the `FibonacciBalance` contract allows all calls to be passed to the library contract, which allows for the `setStart()` function of the library contract to be called also. Recalling that we preserve the state of the contract, it may seem that this function would allow you to change the state of the `start` variable in the local `FibonnacciBalance` contract. If so, this would allow one to withdraw more ether, as the resulting `calculatedFibNumber` is dependent on the `start` variable (as seen in the library contract). In actual fact, the `setStart()` function does not (and cannot) modify the `start` variable in the `FibonacciBalance` contract. The underlying vulnerability in this contract is significantly worse than just modifying the `start` variable.

Before discussing the actual issue, we take a quick detour to understanding how state variables (`storage` variables) actually get stored in contracts. State or `storage` variables (variables that persist over individual transactions) are placed into `slots` sequentially as they are introduced in the contract. (There are some complexities here, and I encourage the reader to read [Layout of State Variables in Storage](http://solidity.readthedocs.io/en/latest/miscellaneous.html#layout-of-state-variables-in-storage) for a more thorough understanding).

As an example, let's look at the library contract. It has two state variables, `start` and `calculatedFibNumber`. The first variable is `start`, as such it gets stored into the contract's storage at `slot[0]` (i.e. the first slot). The second variable, `calculatedFibNumber`, gets placed in the next available storage slot, `slot[1]`. If we look at the function `setStart()`, it takes an input and sets `start` to whatever the input was. This function is therefore setting `slot[0]` to whatever input we provide in the `setStart()` function. Similarly, the `setFibonacci()` function sets `calculatedFibNumber` to the result of `fibonacci(n)`. Again, this is simply setting storage `slot[1]` to the value of `fibonacci(n)`.

Now let's look at the `FibonacciBalance` contract. Storage `slot[0]` now corresponds to `fibonacciLibrary` address and `slot[1]` corresponds to `calculatedFibNumber`. It is in this incorrect mapping that the vulnerability occurs. `delegatecall` **preserves contract context**. This means that code that is executed via `delegatecall` will act on the state (i.e. storage) of the calling contract.

Now notice that in `withdraw()` on line \[21\] we execute, `fibonacciLibrary.delegatecall(fibSig,withdrawalCounter)`. This calls the `setFibonacci()` function, which as we discussed, modifies storage  `slot[1]`, which in our current context is `calculatedFibNumber`. This is as expected (i.e. after execution, `calculatedFibNumber` gets adjusted). However, recall that the `start` variable in the `FibonacciLib` contract is located in storage `slot[0]`, which is the `fibonacciLibrary` address in the current contract. This means that the function `fibonacci()` will give an unexpected result. This is because it references `start` (`slot[0]`) which in the current calling context is the `fibonacciLibrary` address (which will often be quite large, when interpreted as a `uint`). Thus it is likely that the `withdraw()` function will revert as it will not contain `uint(fibonacciLibrary)` amount of ether, which is what `calculatedFibNumber` will return.

Even worse, the `FibonacciBalance` contract allows users to call all of the `fibonacciLibrary` functions via the fallback function on line \[26\]. As we discussed earlier, this includes the `setStart()` function. We discussed that this function allows anyone to modify or set storage `slot[0]`. In this case, storage `slot[0]` is the `fibonacciLibrary` address. Therefore, an attacker could create a malicious contract (an example of one is given below), convert the address to a `uint` (this can be done in python easily using `int('<address>',16)`) and then call `setStart(<attack_contract_address_as_uint>)`. This will change `fibonacciLibrary` to the address of the attack contract. Then, whenever a user calls `withdraw()` or the fallback function, the malicious contract will run (which can steal the entire balance of the contract) because we've modified the actual address for `fibonacciLibrary`. An example of such an attack contract would be,

```solidity
contract Attack {
    uint storageSlot0; // corresponds to fibonacciLibrary
    uint storageSlot1; // corresponds to calculatedFibNumber

    // fallback - this will run if a specified function is not found
    function() public {
        storageSlot1 = 0; // we set calculatedFibNumber to 0, so that if withdraw
        // is called we don't send out any ether.
        <attacker_address>.transfer(this.balance); // we take all the ether
    }
 }
```
Notice that this attack contract modifies the `calculatedFibNumber` by changing storage `slot[1]`. In principle, an attacker could modify any other storage slots they choose to perform all kinds of attacks on this contract. I encourage all readers to put these contracts into [Remix](https://remix.ethereum.org) and experiment with different attack contracts and state changes through these `delegatecall` functions.

It is also important to notice that when we say that `delegatecall` is state-preserving, we are not talking about the variable names of the contract, rather the actual storage slots to which those names point. As you can see from this example, a simple mistake, can lead to an attacker hijacking the entire contract and its ether.

<h3 id="dc-prevention">Preventative Techniques</h3>

Solidity provides the `library` keyword for implementing library contracts (see the [Solidity Docs](http://solidity.readthedocs.io/en/latest/contracts.html?highlight=library#libraries) for further details). This ensures the library contract is stateless and non-self-destructable. Forcing libraries to be stateless mitigates the complexities of storage context demonstrated in this section. Stateless libraries also prevent attacks whereby attackers modify the state of the library directly in order to affect the contracts that depend on the library's code.
As a general rule of thumb, when using `DELEGATECALL` pay careful attention to the possible calling context of both the library contract and the calling contract, and whenever possible, build state-less libraries.

<h3 id="dc-example">Real-World Example: Parity Multisig Wallet (Second Hack)</h3>

The Second Parity Multisig Wallet hack is an example of how the context of well-written library code can be exploited if run in its non-intended context. There are a number of good explanations of this hack, such as this overview: [Parity MultiSig Hacked. Again](https://medium.com/chain-cloud-company-blog/parity-multisig-hack-again-b46771eaa838) by Anthony Akentiev, this [stack exchange question](https://ethereum.stackexchange.com/questions/30128/explanation-of-parity-library-suicide/30130) and [An In-Depth Look at the Parity Multisig Bug](http://hackingdistributed.com/2017/07/22/deep-dive-parity-bug/).

To add to these references, let's explore the contracts that were exploited. The library and wallet contract can be found on the parity github [here](https://github.com/paritytech/parity/blob/b640df8fbb964da7538eef268dffc125b081a82f/js/src/contracts/snippets/enhanced-wallet.sol).

Let's look at the relevant aspects of this contract. There are two contracts of interest contained here, the library contract and the wallet contract.

The library contract,
```solidity
contract WalletLibrary is WalletEvents {

  ...

  // throw unless the contract is not yet initialized.
  modifier only_uninitialized { if (m_numOwners > 0) throw; _; }

  // constructor - just pass on the owner array to the multiowned and
  // the limit to daylimit
  function initWallet(address[] _owners, uint _required, uint _daylimit) only_uninitialized {
    initDaylimit(_daylimit);
    initMultiowned(_owners, _required);
  }

  // kills the contract sending everything to `_to`.
  function kill(address _to) onlymanyowners(sha3(msg.data)) external {
    suicide(_to);
  }

  ...

}
```

and the wallet contract,

```solidity
contract Wallet is WalletEvents {

  ...

  // METHODS

  // gets called when no other function matches
  function() payable {
    // just being sent some cash?
    if (msg.value > 0)
      Deposit(msg.sender, msg.value);
    else if (msg.data.length > 0)
      _walletLibrary.delegatecall(msg.data);
  }

  ...

  // FIELDS
  address constant _walletLibrary = 0xcafecafecafecafecafecafecafecafecafecafe;
}
```
Notice that the `Wallet` contract essentially passes all calls to the `WalletLibrary` contract via a delegate call. The constant `_walletLibrary` address in this code snippet acts as a placeholder for the actually deployed `WalletLibrary` contract (which was at `0x863DF6BFa4469f3ead0bE8f9F2AAE51c91A907b4`).

The intended operation of these contracts was to have a simple low-cost deployable `Wallet` contract whose code base and main functionality was in the `WalletLibrary` contract. Unfortunately, the `WalletLibrary` contract is itself a contract and maintains it's own state. Can you see why this might be an issue?

It is possible to send calls to the `WalletLibrary` contract itself. Specifically, the `WalletLibrary` contract could be initialised, and become owned. A user did this, by calling `initWallet()` function on the `WalletLibrary` contract, becoming an owner of the library contract. The same user, subsequently called the `kill()` function. Because the user was an owner of the Library contract, the modifier passed and the library contract suicided. As all `Wallet` contracts in existence refer to this library contract and contain no method to change this reference, all of their functionality, including the ability to withdraw ether is lost along with the `WalletLibrary` contract. More directly, all ether in all parity multi-sig wallets of this type instantly become lost or permanently unrecoverable.

<h2 id="visibility"><span id="SP-5">5. Default Visibilities</span></h2>

Functions in Solidity have visibility specifiers which dictate how functions are allowed to be called. The visibility determines whether a function can be called externally by users, by other derived contracts, only internally or only externally. There are four visibility specifiers, which are described in detail in the [Solidity Docs](http://solidity.readthedocs.io/en/latest/contracts.html?highlight=library#visibility-and-getters). Functions default to `public` allowing users to call them externally. Incorrect use of visibility specifiers can lead to some devestating vulernabilities in smart contracts as will be discussed in this section.

<h3 id="visibility-vuln">The Vulnerability</h3>

The default visibility for functions is `public`. Therefore functions that do not specify any visibility will be callable by external users.  The issue comes when developers mistakenly ignore visibility specifiers on functions which should be private (or only callable within the contract itself).

Let's quickly explore a trivial example.

```solidity
contract HashForEther {

    function withdrawWinnings() {
        // Winner if the last 8 hex characters of the address are 0.
        require(uint32(msg.sender) == 0);
        _sendWinnings();
     }

     function _sendWinnings() {
         msg.sender.transfer(this.balance);
     }
}
```

This simple contract is designed to act as an address guessing bounty game. To win the balance of the contract, a user must generate an Ethereum address whose last 8 hex characters are 0. Once obtained, they can call the `WithdrawWinnings()` function to obtain their bounty.

Unfortunately, the visibility of the functions have not been specified. In particular, the `_sendWinnings()` function is `public` and thus any address can call this function to steal the bounty.

<h3 id="visibility-prevention">Preventative Techniques</h3>

It is good practice to always specify the visibility of all functions in a contract, even if they are intentionally `public`. Recent versions of Solidity will now show warnings during compilation for functions that have no explicit visibility set, to help encourage this practice.

<h3 id="visibility-example">Real-World Example: Parity MultiSig Wallet (First Hack)</h3>

In the first Parity multi-sig hack, about \$31M worth of Ether was stolen from primarily three wallets. A good recap of exactly how this was done is given by Haseeb Qureshi in [this post](https://medium.freecodecamp.org/a-hacker-stole-31m-of-ether-how-it-happened-and-what-it-means-for-ethereum-9e5dc29e33ce).

Essentially, the multi-sig wallet (which can be found [here](https://github.com/paritytech/parity/blob/4d08e7b0aec46443bf26547b17d10cb302672835/js/src/contracts/snippets/enhanced-wallet.sol)) is constructed from a base `Wallet` contract which calls a library contract containing the core functionality (as was described in [Real-World Example: Parity Multisig (Second Hack)](#dc-example)). The library contract contains the code to initialise the wallet as can be seen from the following snippet
```solidity
contract WalletLibrary is WalletEvents {

  ...

  // METHODS

  ...

  // constructor is given number of sigs required to do protected "onlymanyowners" transactions
  // as well as the selection of addresses capable of confirming them.
  function initMultiowned(address[] _owners, uint _required) {
    m_numOwners = _owners.length + 1;
    m_owners[1] = uint(msg.sender);
    m_ownerIndex[uint(msg.sender)] = 1;
    for (uint i = 0; i < _owners.length; ++i)
    {
      m_owners[2 + i] = uint(_owners[i]);
      m_ownerIndex[uint(_owners[i])] = 2 + i;
    }
    m_required = _required;
  }

  ...

  // constructor - just pass on the owner array to the multiowned and
  // the limit to daylimit
  function initWallet(address[] _owners, uint _required, uint _daylimit) {
    initDaylimit(_daylimit);
    initMultiowned(_owners, _required);
  }
}
```

Notice that neither of the functions have explicitly specified a visibility. Both functions default to `public`. The `initWallet()` function is called in the wallets constructor and sets the owners for the multi-sig wallet as can be seen in the `initMultiowned()` function. Because these functions were accidentally left `public`, an attacker was able to call these functions on deployed contracts, resetting the ownership to the attackers address. Being the owner, the attacker then drained the wallets of all their ether, to the tune of \$31M.

<h2 id="entropy"><span id="SP-6">6. Entropy Illusion</span></h2>

All transactions on the Ethereum blockchain are deterministic state transition operations. Meaning that every transaction modifies the global state of the Ethereum ecosystem and it does so in a calculable way with no uncertainty. This ultimately means that inside the blockchain ecosystem there is no source of entropy or randomness. There is no `rand()` function in Solidity. Achieving decentralised entropy (randomness) is a well established problem and many ideas have been proposed to address this (see for example, [RandDAO](https://github.com/randao/randao) or using a chain of Hashes as described by Vitalik in this [post](https://vitalik.ca/files/randomness.html)).

<h3 id="entropy-vuln">The Vulnerability</h3>

Some of the first contracts built on the Ethereum platform were based around gambling. Fundamentally, gambling requires uncertainty (something to bet on), which makes building a gambling system on the blockchain (a deterministic system) rather difficult. It is clear that the uncertainty must come from a source external to the blockchain. This is possible for bets amongst peers (see for example the [commit-reveal technique](https://ethereum.stackexchange.com/questions/191/how-can-i-securely-generate-a-random-number-in-my-smart-contract)), however, it is significantly more difficult if you want to implement a contract to act as *the house* (like in blackjack our roulette). A common pitfall is to use future block variables, such as hashes, timestamps, blocknumber or gas limit. The issue with these are that they are controlled by the miner who mines the block and as such are not truly random. Consider, for example, a roulette smart contract with logic that returns a black number if the next block hash ends in an even number. A miner (or miner pool) could bet \\$1M on black. If they solve the next block and find the hash ends in an odd number, they would happily not publish their block and mine another until they find a solution with the block hash being an even number (assuming the block reward and fees are less than $1M). Using past or present variables can be even more devastating as Martin Swende demonstrates in his excellent [blog post](http://martin.swende.se/blog/Breaking_the_house.html). Furthermore, using solely block variables mean that the pseudo-random number will be the same for all transactions in a block, so an attacker can multiply their wins by doing many transactions within a block (should there be a maximum bet).

<h3 id="entropy-prevention">Preventative Techniques</h3>

The source of entropy (randomness) must be external to the blockchain. This can be done amongst peers with systems such as [commit-reveal](https://ethereum.stackexchange.com/questions/191/how-can-i-securely-generate-a-random-number-in-my-smart-contract), or via changing the trust model to a group of participants (such as in [RandDAO](https://github.com/randao/randao)). This can also be done via a centralised entity, which acts as a randomness oracle. Block variables (in general, there are some exceptions) should not be used to source entropy as they can be manipulated by miners.

<h3 id="entropy-example">Real-World Example: PRNG Contracts</h3>

Arseny Reutov wrote a [blog post](https://blog.positive.com/predicting-random-numbers-in-ethereum-smart-contracts-e5358c6b8620) after he analysed 3649 live smart contracts which were using some sort of pseudo random number generator (PRNG) and found 43 contracts which could be exploited.

<h2 id="contract-reference"><span id="SP-7">7. External Contract Referencing</span></h2>

One of the benefits of the Ethereum *global computer* is the ability to re-use code and interact with contracts already deployed on the network. As a result, a large number of contracts reference external contracts and in general operation use external message calls to interact with these contracts. These external message calls can mask malicious actors intentions in some non-obvious ways, which we will discuss.

<h3 id="cr-vuln">The Vulnerability</h3>

In Solidity, any address can be cast as a contract regardless of whether the code at the address represents the contract type being cast. This can be deceiving, especially when the author of the contract is trying to hide malicious code. Let us illustrate this with an example:

Consider a piece of code which rudimentarily implements the [Rot13](www.wikipedia.com/rot13) cipher.

`Rot13Encryption.sol`:
```solidity
//encryption contract
contract Rot13Encryption {

   event Result(string convertedString);

    //rot13 encrypt a string
    function rot13Encrypt (string text) public {
        uint256 length = bytes(text).length;
        for (var i = 0; i < length; i++) {
            byte char = bytes(text)[i];
            //inline assembly to modify the string
            assembly {
                char := byte(0,char) // get the first byte
                if and(gt(char,0x6D), lt(char,0x7B)) // if the character is in [n,z], i.e. wrapping.
                { char:= sub(0x60, sub(0x7A,char)) } // subtract from the ascii number a by the difference char is from z.
                if iszero(eq(char, 0x20)) // ignore spaces
                {mstore8(add(add(text,0x20), mul(i,1)), add(char,13))} // add 13 to char.
            }
        }
        emit Result(text);
    }

    // rot13 decrypt a string
    function rot13Decrypt (string text) public {
        uint256 length = bytes(text).length;
        for (var i = 0; i < length; i++) {
            byte char = bytes(text)[i];
            assembly {
                char := byte(0,char)
                if and(gt(char,0x60), lt(char,0x6E))
                { char:= add(0x7B, sub(char,0x61)) }
                if iszero(eq(char, 0x20))
                {mstore8(add(add(text,0x20), mul(i,1)), sub(char,13))}
            }
        }
        emit Result(text);
    }
}
```
This code simply takes a string (letters a-z, without validation) and *encrypts* it by shifting each character 13 places to the right (wrapping around 'z'); i.e. 'a' shifts to 'n' and 'x' shifts to 'k'. The assembly in here is not important, so don't worry if it doesn't make any sense at this stage.

Consider the following contract which uses this code for its encryption,
```solidity
import "Rot13Encryption.sol";

// encrypt your top secret info
contract EncryptionContract {
    // library for encryption
    Rot13Encryption encryptionLibrary;

    // constructor - initialise the library
    constructor(Rot13Encryption _encryptionLibrary) {
        encryptionLibrary = _encryptionLibrary;
    }

    function encryptPrivateData(string privateInfo) {
        // potentially do some operations here
        encryptionLibrary.rot13Encrypt(privateInfo);
     }
 }
```


The issue with this contract is that the `encryptionLibrary` address is not public or constant. Thus the deployer of the contract could have given an address in the constructor which points to this contract:




```solidity
//encryption contract
contract Rot26Encryption {

   event Result(string convertedString);

    //rot13 encrypt a string
    function rot13Encrypt (string text) public {
        uint256 length = bytes(text).length;
        for (var i = 0; i < length; i++) {
            byte char = bytes(text)[i];
            //inline assembly to modify the string
            assembly {
                char := byte(0,char) // get the first byte
                if and(gt(char,0x6D), lt(char,0x7B)) // if the character is in [n,z], i.e. wrapping.
                { char:= sub(0x60, sub(0x7A,char)) } // subtract from the ascii number a by the difference char is from z.
                if iszero(eq(char, 0x20)) // ignore spaces
                {mstore8(add(add(text,0x20), mul(i,1)), add(char,26))} // add 13 to char.
            }
        }
        emit Result(text);
    }

    // rot13 decrypt a string
    function rot13Decrypt (string text) public {
        uint256 length = bytes(text).length;
        for (var i = 0; i < length; i++) {
            byte char = bytes(text)[i];
            assembly {
                char := byte(0,char)
                if and(gt(char,0x60), lt(char,0x6E))
                { char:= add(0x7B, sub(char,0x61)) }
                if iszero(eq(char, 0x20))
                {mstore8(add(add(text,0x20), mul(i,1)), sub(char,26))}
            }
        }
        emit Result(text);
    }
}
```
which implements the rot26 cipher (shifts each character by 26 places, get it? :p). Again, there is no need to understand the assembly in this contract. The deployer could have also linked the following contract:

```solidity
contract Print{
    event Print(string text);

    function rot13Encrypt(string text) public {
        emit Print(text);
    }
 }

```
 If the address of either of these contracts were given in the constructor, the `encryptPrivateData()` function would simply produce an event which prints the unencrypted private data. Although in this example a library-like contract was set in the constructor, it is often the case that a privileged user (such as an `owner`) can change library contract addresses. If a linked contract doesn't contain the function being called, the fallback function will execute. For example, with the line `encryptionLibrary.rot13Encrypt()`, if the contract specified by `encryptionLibrary` was:
```solidity
 contract Blank {
     event Print(string text);
     function () {
         emit Print("Here");
         //put malicious code here and it will run
     }
 }
```
then an event with the text "Here" would be emitted. Thus if users can alter contract libraries, they can in principle get users to unknowingly run arbitrary code.

*Note: Don't use encryption contracts such as these, as the input parameters to smart contracts are visible on the blockchain. Also the Rot cipher is not a recommended encryption technique :p*


<h3 id="cr-prevention">Preventative Techniques</h3>

As demonstrated above, vulnerability free contracts can (in some cases) be deployed in such a way that they behave maliciously. An auditor could publicly verify a contract and have it's owner deploy it in a malicious way, resulting in a publicly audited contract which has vulnerabilities or malicious intent.

There are a number of techniques which prevent these scenarios.

One technique, is to use the `new` keyword to create contracts. In the example above, the constructor could be written like:

```solidity
    constructor() {
        encryptionLibrary = new Rot13Encryption();
    }
```
This way an instance of the referenced contract is created at deployment time and the deployer cannot replace the `Rot13Encryption` contract with anything else without modifying the smart contract.

Another solution is to hard code any external contract addresses if they are known.

In general, code that calls external contracts should always be looked at carefully. As a developer, when defining external contracts, it can be a good idea to make the contract addresses public (which is not the case in the honey-pot example given below) to allow users to easily examine which code is being referenced by the contract. Conversely, if a contract has a private variable contract address it can be a sign of someone behaving maliciously (as shown in the real-world example). If a privileged (or any) user is capable of changing a contract address which is used to call external functions, it can be important (in a decentralised system context) to implement a time-lock or voting mechanism to allow users to see which code is being changed or to give participants a chance to opt in/out with the new contract address.


<h3 id="cr-example">Real-World Example: Re-Entrancy Honey Pot</h3>

A number of recent honey pots have been released on the mainnet. These contracts try to outsmart Ethereum hackers who try to exploit the contracts, but who in turn end up getting ether lost to the contract they expect to exploit. One example employs the above attack by replacing an expected contract with a malicious one in the constructor. The code can be found [here](https://etherscan.io/address/0x95d34980095380851902ccd9a1fb4c813c2cb639#code):
```solidity
pragma solidity ^0.4.19;

contract Private_Bank
{
    mapping (address => uint) public balances;
    uint public MinDeposit = 1 ether;
    Log TransferLog;

    function Private_Bank(address _log)
    {
        TransferLog = Log(_log);
    }

    function Deposit()
    public
    payable
    {
        if(msg.value >= MinDeposit)
        {
            balances[msg.sender]+=msg.value;
            TransferLog.AddMessage(msg.sender,msg.value,"Deposit");
        }
    }

    function CashOut(uint _am)
    {
        if(_am<=balances[msg.sender])
        {
            if(msg.sender.call.value(_am)())
            {
                balances[msg.sender]-=_am;
                TransferLog.AddMessage(msg.sender,_am,"CashOut");
            }
        }
    }

    function() public payable{}

}

contract Log
{
    struct Message
    {
        address Sender;
        string  Data;
        uint Val;
        uint  Time;
    }

    Message[] public History;
    Message LastMsg;

    function AddMessage(address _adr,uint _val,string _data)
    public
    {
        LastMsg.Sender = _adr;
        LastMsg.Time = now;
        LastMsg.Val = _val;
        LastMsg.Data = _data;
        History.push(LastMsg);
    }
}

```

This [post](https://www.reddit.com/r/ethdev/comments/7x5rwr/tricked_by_a_honeypot_contract_or_beaten_by/) by one reddit user explains how they lost 1 ether to this contract by trying to exploit the re-entrancy bug they expected to be present in the contract.



<h2 id="short-address"><span id="SP-8">8. Short Address/Parameter Attack</span></h2>


This attack is not specifically performed on Solidity contracts themselves but on third party applications that may interact with them. I add this attack for completeness and to be aware of how parameters can be manipulated in contracts.

For further reading, see [The ERC20 Short Address Attack Explained](https://vessenes.com/the-erc20-short-address-attack-explained/), [ICO Smart contract Vulnerability: Short Address Attack](https://medium.com/huzzle/ico-smart-contract-vulnerability-short-address-attack-31ac9177eb6b) or this [reddit post](https://www.reddit.com/r/ethereum/comments/6r9nhj/cant_understand_the_erc20_short_address_attack/).


<h3 id="short-vuln">The Vulnerability</h3>

When passing parameters to a smart contract, the parameters are encoded according to the [ABI specification](https://solidity.readthedocs.io/en/latest/abi-spec.html). It is possible to send encoded parameters that are shorter than the expected parameter length (for example, sending an address that is only 38 hex chars (19 bytes) instead of the standard 40 hex chars (20 bytes)). In such a scenario, the EVM will pad 0's to the end of the encoded parameters to make up the expected length.

This becomes an issue when third party applications do not validate inputs. The clearest example is an exchange which doesn't verify the address of an [ERC20](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md) token when a user requests a withdrawal. This example is covered in more detail in Peter Venesses' post, [The ERC20 Short Address Attack Explained](http://vessenes.com/the-erc20-short-address-attack-explained/) mentioned above.

Consider, the standard [ERC20](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md) transfer function interface, noting the order of the parameters,
```solidity
function transfer(address to, uint tokens) public returns (bool success);
```
Now consider, an exchange, holding a large amount of a token (let's say `REP`) and a user wishes to withdraw their share of 100 tokens. The user would submit their address, `0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead` and the number of tokens, `100`. The exchange would encode these parameters in the order specified by the `transfer()` function, i.e. `address` then `tokens`. The encoded result would be `a9059cbb000000000000000000000000deaddeaddeaddeaddeaddeaddeaddeaddeaddead0000000000000` `000000000000000000000000000000000056bc75e2d63100000`. The first four bytes (`a9059cbb`) are the `transfer()` [function signature/selector](https://solidity.readthedocs.io/en/latest/abi-spec.html#function-selector), the second 32 bytes are the address, followed by the final 32 bytes which represent the `uint256` number of tokens. Notice that the hex `56bc75e2d63100000` at the end corresponds to 100 tokens (with 18 decimal places, as specified by the `REP` token contract).

Ok, so now let's look at what happens if we were to send an address that was missing 1 byte (2 hex digits). Specifically, let's say an attacker sends `0xdeaddeaddeaddeaddeaddeaddeaddeaddeadde`as an address (missing the last two digits) and the same  `100` tokens to withdraw. If the exchange doesn't validate this input, it would get encoded as `a9059cbb000000000000000000000000deaddeaddeaddeaddeaddeaddeaddeaddeadde00000000000000` `00000000000000000000000000000000056bc75e2d6310000000`. The difference is subtle. Note that `00` has been padded to the end of the encoding, to make up for the short address that was sent. When this gets sent to the smart contract, the `address` parameters will read as `0xdeaddeaddeaddeaddeaddeaddeaddeaddeadde00` and the value will be read as `56bc75e2d6310000000` (notice the two extra `0`'s). This value is now, `25600` tokens (the value has been multiplied by `256`). In this example, if the exchange held this many tokens, the user would withdraw `25600` tokens (whilst the exchange thinks the user is only withdrawing `100`) to the modified address. Obviously the attacker won't possess the modified address in this example, but if the attacker were to generate any address which ended in `0`'s (which can be easily brute forced) and used this generated address, they could easily steal tokens from the unsuspecting exchange.

<h3 id="short-prev">Preventative Techniques</h3>

I suppose it is obvious to say that validating all inputs before sending them to the blockchain will prevent these kinds of attacks. It should also be noted that parameter ordering plays an important role here. As padding only occurs at the end, careful ordering of parameters in the smart contract can potentially mitigate some forms of this attack.

<h3 id="short-example">Real-World Example: Unknown</h3>

I do not know of any publicised attack of this kind in the wild.

<h2 id="unchecked-calls"><span id="SP-9">9. Unchecked CALL Return Values</span></h2>

There a number of ways of performing external calls in solidity. Sending ether to external accounts is commonly performed via the `transfer()` method.  However, the `send()` function can also be used and, for more versatile external calls, the `CALL` opcode can be directly employed in solidity. The `call()` and `send()` functions return a boolean indicating if the call succeeded or failed. Thus these functions have a simple caveat, in that the transaction that executes these functions will not revert if the external call (initialised by `call()` or `send()`) fails, rather the `call()` or `send()` will simply return `false`. A common pitfall arises when the return value is not checked, rather the developer expects a revert to occur.

For further reading, see [DASP Top 10](http://www.dasp.co/#item-4) and [Scanning Live Ethereum Contracts for the "Unchecked-Send" Bug](http://hackingdistributed.com/2016/06/16/scanning-live-ethereum-contracts-for-bugs/).

<h3 id="unchecked-calls-vuln">The Vulnerability</h3>

Consider the following example:

```solidity
contract Lotto {

    bool public payedOut = false;
    address public winner;
    uint public winAmount;

    // ... extra functionality here

    function sendToWinner() public {
        require(!payedOut);
        winner.send(winAmount);
        payedOut = true;
    }

    function withdrawLeftOver() public {
        require(payedOut);
        msg.sender.send(this.balance);
    }
}
```

This contract represents a Lotto-like contract, where a `winner` receives `winAmount` of ether, which typically leaves a little left over for anyone to withdraw.

The bug exists on line \[11\] where a `send()` is used without checking the response. In this trivial example, a `winner` whose transaction fails (either by running out of gas or being a contract that intentionally throws in the fallback function) allows `payedOut` to be set to `true` (regardless of whether ether was sent or not). In this case, the public can withdraw the `winner`'s winnings via the `withdrawLeftOver()` function.

<h3 id="unchecked-calls-prev">Preventative Techniques</h3>

Whenever possible, use the `transfer()` function rather than `send()` as `transfer()` will `revert` if the external transaction reverts. If `send()` is required, always ensure to check the return value.

An even more robust [recommendation](http://solidity.readthedocs.io/en/latest/common-patterns.html#withdrawal-from-contracts) is to adopt a *withdrawal pattern*. In this solution, each user is burdened with calling an isolated function (i.e. a *withdraw* function) which handles the sending of ether out of the contract and therefore independently deals with the consequences of failed send transactions. The idea is to logically isolate the external send functionality from the rest of the code base and place the burden of potentially failed transaction to the end-user who is calling the *withdraw* function.

<h3 id="unchecked-calls-example">Real-World Example: Etherpot and King of the Ether</h3>

[Etherpot](https://github.com/etherpot) was a smart contract lottery, not too dissimilar to the example contract mentioned above. The solidity code for etherpot, can be found here: [lotto.sol](https://github.com/etherpot/contract/blob/master/app/contracts/lotto.sol). The primary downfall of this contract was due to an incorrect use of block hashes (only the last 256 block hashes are useable, see Aakil Fernandes's [post](http://aakilfernandes.github.io/blockhashes-are-only-good-for-256-blocks) about how Etherpot failed to implement this correctly). However this contract also suffered from an unchecked call value. Notice the function, `cash()` on line \[80\] of lotto.sol:

```solidity
...
  function cash(uint roundIndex, uint subpotIndex){

        var subpotsCount = getSubpotsCount(roundIndex);

        if(subpotIndex>=subpotsCount)
            return;

        var decisionBlockNumber = getDecisionBlockNumber(roundIndex,subpotIndex);

        if(decisionBlockNumber>block.number)
            return;

        if(rounds[roundIndex].isCashed[subpotIndex])
            return;
        //Subpots can only be cashed once. This is to prevent double payouts

        var winner = calculateWinner(roundIndex,subpotIndex);
        var subpot = getSubpot(roundIndex);

        winner.send(subpot);

        rounds[roundIndex].isCashed[subpotIndex] = true;
        //Mark the round as cashed
}
...
```
Notice that on line \[21\] the send function's return value is not checked, and the following line then sets a boolean indicating the winner has been sent their funds. This bug can allow a state where the winner does not receive their ether, but the state of the contract can indicate that the winner has already been paid.

A more serious version of this bug occurred in the [King of the Ether](https://www.kingoftheether.com/thrones/kingoftheether/index.html). An excellent [post-mortem](https://www.kingoftheether.com/postmortem.html) of this contract has been written which details how an unchecked failed `send()` could be used to attack the contract.


<h2 id="race-conditions"><span id="SP-10">10. Race Conditions / Front Running</span></h2>

The combination of external calls to other contracts and the multi-user nature of the underlying blockchain gives rise to a variety of potential Solidity pitfalls whereby users *race* code execution to obtain unexpected states. [Re-Entrancy](#reentrancy) is one example of such a race condition. In this section we will talk more generally about different kinds of race conditions that can occur on the Ethereum blockchain. There is a variety of good posts on this subject, a few are: [Ethereum Wiki - Safety](https://github.com/ethereum/wiki/wiki/Safety#race-conditions), [DASP - Front-Running](http://www.dasp.co/#item-7) and the [Consensus - Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/known_attacks/#race-conditions).

<h3 id="race-conditions-vuln">The Vulnerability</h3>

As with most blockchains, Ethereum nodes pool transactions and form them into blocks. The transactions are only considered valid once a miner has solved a consensus mechanism (currently [ETHASH](https://github.com/ethereum/wiki/wiki/Ethash) PoW for Ethereum). The miner who solves the block also chooses which transactions from the pool will be included in the block, this is typically ordered by the `gasPrice` of a transaction. In here lies a potential attack vector. An attacker can watch the transaction pool for transactions which may contain solutions to problems, modify or revoke the attacker's permissions or change a state in a contract which is undesirable for the attacker. The attacker can then get the data from this transaction and create a transaction of their own with a higher `gasPrice` and get their transaction included in a block before the original.

Let's see how this could work with a simple example. Consider the contract `FindThisHash.sol`:

```solidity
contract FindThisHash {
    bytes32 constant public hash = 0xb5b5b97fafd9855eec9b41f74dfb6c38f5951141f9a3ecd7f44d5479b630ee0a;

    constructor() public payable {} // load with ether

    function solve(string solution) public {
        // If you can find the pre image of the hash, receive 1000 ether
        require(hash == sha3(solution));
        msg.sender.transfer(1000 ether);
    }
}
```
Imagine this contract contains 1000 ether. The user who can find the pre-image of the sha3 hash `0xb5b5b97fafd9855eec9b41f74dfb6c38f5951141f9a3ecd7f44d5479b630ee0a` can submit the solution and retrieve the 1000 ether. Let's say one user figures out the solution is `Ethereum!`. They call `solve()` with `Ethereum!` as the parameter. Unfortunately an attacker has been clever enough to watch the transaction pool for anyone submitting a solution. They see this solution, check it's validity, and then submit an equivalent transaction with a much higher `gasPrice` than the original transaction. The miner who solves the block will likely give the attacker preference due to the higher `gasPrice` and accept their transaction before the original solver. The attacker will take the 1000 ether and the user who solved the problem will get nothing (there is no ether left in the contract).

A more realistic problem comes in the design of the future Casper implementation. The Casper proof of stake contracts invoke slashing conditions where users who notice validators double-voting or misbehaving are incentivised to submit proof that they have done so. The validator will be punished and the user rewarded. In such a scenario, it is expected that miners and users will front-run all such submissions of proof, and this issue must be addressed before the final release.

<h3 id="race-conditions-prev">Preventative Techniques</h3>

There are two classes of users who can perform these kinds of front-running attacks. Users (who modify the `gasPrice` of their transactions) and miners themselves (who can re-order the transactions in a block how they see fit). A contract that is vulnerable to the first class (users), is significantly worse-off than one vulnerable to the second (miners) as miner's can only perform the attack when they solve a block, which is unlikely for any individual miner targeting a specific block. Here I'll list a few mitigation measures with relation to which class of attackers they may prevent.

One method that can be employed is to create logic in the contract that places an upper bound on the `gasPrice`. This prevents users from increasing the `gasPrice` and getting preferential transaction ordering beyond the upper-bound. This preventative measure only mitigates the first class of attackers (arbitrary users). Miners in this scenario can still attack the contract as they can order the transactions in their block however they like, regardless of gas price.

A more robust method is to use a [commit-reveal](https://ethereum.stackexchange.com/questions/191/how-can-i-securely-generate-a-random-number-in-my-smart-contract) scheme, whenever possible. Such a scheme dictates users send transactions with hidden information (typically a hash). After the transaction has been included in a block, the user sends a transaction revealing the data that was sent (the reveal phase). This method prevents both miners and users from frontrunning transactions as they cannot determine the contents of the transaction. This method however, cannot conceal the transaction value (which in some cases is the valuable information that needs to be hidden). The [ENS](https://ens.domains/)  smart contract allowed users to send transactions, whose committed data included the amount of ether they were willing to spend. Users could then send transactions of arbitrary value. During the reveal phase, users were refunded the difference between the amount sent in the transaction and the amount they were willing to spend.



A further suggestion by Lorenz, Phil, Ari and Florian is to use [Submarine Sends](http://hackingdistributed.com/2017/08/28/submarine-sends/). An efficient implementation of this idea requires the `CREATE2` opcode, which currently hasn't been adopted, but seems likely in upcoming hard forks.

<h3 id="race-conditions-example">Real-World Examples: ERC20 and Bancor</h3>

The [ERC20](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md) standard is quite well-known for building tokens on Ethereum. This standard has a potential frontrunning vulnerability which comes about due to the `approve()` function. A good explanation of this vulnerability can be found [here](https://docs.google.com/document/d/1YLPtQxZu1UAvO9cZ1O2RPXBbT0mooh4DYKjA_jp-RLM/edit).

The standard specifies the `approve()` function as:
```solidity
function approve(address _spender, uint256 _value) returns (bool success)
```
This function allows a user to permit other users to transfer tokens on their behalf. The frontrunning vulnerability comes in the scenario when a user, Alice, *approves* her friend, `Bob` to spend `100 tokens`. Alice later decides that she wants to revoke `Bob`'s approval to spend `100 tokens`, so she creates a transaction that sets `Bob`'s allocation to `50 tokens`. `Bob`, who has been carefully watching the chain, sees this transaction and builds a transaction of his own spending the `100 tokens`. He puts a higher `gasPrice` on his transaction than `Alice`'s and gets his transaction prioritised over hers. Some implementations of `approve()` would allow `Bob` to transfer his `100 tokens`, then when `Alice`'s transaction gets committed, resets `Bob`'s approval to `50 tokens`, in effect giving `Bob` access to `150 tokens`. The mitigation strategies of this attack are given [here](https://docs.google.com/document/d/1YLPtQxZu1UAvO9cZ1O2RPXBbT0mooh4DYKjA_jp-RLM/edit) in the document linked above.

Another prominent, real-world example is [Bancor](https://www.bancor.network/). Ivan Bogatty and his team documented a profitable attack on the initial Bancor implementation. His [blog post](https://hackernoon.com/front-running-bancor-in-150-lines-of-python-with-ethereum-api-d5e2bfd0d798) and [Devon 3 talk](https://www.youtube.com/watch?v=RL2nE3huNiI) discuss in detail how this was done. Essentially, prices of tokens are determined based on transaction value, users can watch the transaction pool for Bancor transactions and front run them to profit from the price differences. This attack has been addressed by the Bancor team.

<h2 id="dos"><span id="SP-11">11. Denial Of Service (DOS)</span></h2>

This category is very broad, but fundamentally consists of attacks where users can leave the contract inoperable for a small period of time, or in some cases, permanently. This can trap ether in these contracts forever, as was the case with the [Second Parity MultiSig hack](#dc-example)

<h3 id="dos-vuln">The Vulnerability</h3>

There are various ways a contract can become inoperable. Here I will only highlight some potentially less-obvious Blockchain nuanced Solidity coding patterns that can lead to attackers performing DOS attacks.

**1. External calls without gas stipends** - It may be the case that you wish
to make an external call to an unknown contract and continue processing the
transaction regardless whether that call fails or not. Typically this is
achieved by using the `CALL` opcode, which does not revert the transaction
if the call fails (see [Unchecked CALL Return Values](#unchecked-calls) for further details and examples).
Let us consider a simple example, where we have a contract wallet, that slowly
trickles out ether when the `withdraw()` function is called. A `partner` can
add their address and spend gas to call the withdraw, giving both the
`partner` and the `owner` 1% of the total contract balance.

```solidity
contract TrickleWallet {

    address public partner; // withdrawal partner - pay the gas, split the withdraw
    address public constant owner = 0xA9E;
    uint timeLastWithdrawn;
    mapping(address => uint) withdrawPartnerBalances; // keep track of partners balances

    function setWithdrawPartner(address _partner) public {
        require(partner == '0x0' || msg.sender == partner);
        partner = _partner;
    }

    // withdraw 1% to recipient and 1% to owner
    function withdraw() public {
        uint amountToSend = address(this).balance/100;
        // perform a call without checking return
        // the recipient can revert, the owner will still get their share
        partner.call.value(amountToSend)();
        owner.transfer(amountToSend);
        // keep track of last withdrawal time
        timeLastWithdrawn = now;
        withdrawPartnerBalances[partner] += amountToSend;
    }

    // allow deposit of funds
    function() payable {}

    // convenience function
    function contractBalance() view returns (uint) {
        return address(this).balance;
    }
}
```

Notice that on line \[17\] we perform an external call sending 1% of the
contract balance  to a user-specified account. The reason the `CALL` opcode is used, is to ensure that
the owner still gets paid, even if the external call reverts. The issue is that
the transaction will send all of its gas (in reality, only most of the transaction gas is sent, some is left to finish processing the call) to the external call. If the user were malicious they could create a contract that would consume all the gas, and force all transactions to `withdraw()` to fail, due to running out of gas.

For example, consider the following malicious contract that consumes all gas,
```solidity
contract ConsumeAllGas {
    function () payable {
        // an assert consumes all transaction gas, unlike a
        //revert which returns the remaining gas
        assert(1==2);
    }
}
```
If a withdrawal partner decided they didn't like the owner of the contract.
They could set the partner address to this contract and lock all the funds in
the `TrickleWallet` contract forever.

To prevent such DOS attack vectors, ensure a gas stipend is specified in an
external call, to limit the amount of gas that that transaction can use. In our
example, we could remedy this attack by changing line \[17\] to:
```solidity
partner.call.gas(50000).value(amountToSend)();
```
This modification allows only 50,000 gas to be spent on the external
transaction. The `owner` may set a gas price larger than this, in order to have
their transaction complete, regardless of how much the external transaction
uses.

**2. Looping through externally manipulated mappings or arrays** - In my adventures I've seen various forms of this kind of pattern. Typically it appears in scenarios where an `owner` wishes to distribute tokens amongst their investors, and do so with a `distribute()`-like function as can be seen in the example contract:

```solidity
contract DistributeTokens {
    address public owner; // gets set somewhere
    address[] investors; // array of investors
    uint[] investorTokens; // the amount of tokens each investor gets

    // ... extra functionality, including transfertoken()

    function invest() public payable {
        investors.push(msg.sender);
        investorTokens.push(msg.value * 5); // 5 times the wei sent
        }

    function distribute() public {
        require(msg.sender == owner); // only owner
        for(uint i = 0; i < investors.length; i++) {
            // here transferToken(to,amount) transfers "amount" of tokens to the address "to"
            transferToken(investors[i],investorTokens[i]);
        }
    }
}
```

Notice that the loop in this contract runs over an array which can be artificially inflated. An attacker can create many user accounts making the `investor` array large. In principle this can be done such that the gas required to execute the for loop exceeds the block gas limit, essentially making the `distribute()` function inoperable.

**3. Owner operations** - Another common pattern is where owners have specific privileges in contracts and must perform some task in order for the contract to proceed to the next state. One example would be an ICO contract that requires the owner to `finalize()` the contract which then allows tokens to be transferable, i.e.
``` solidity
bool public isFinalized = false;
address public owner; // gets set somewhere

function finalize() public {
    require(msg.sender == owner);
    isFinalized == true;
}

// ... extra ICO functionality

// overloaded transfer function
function transfer(address _to, uint _value) returns (bool) {
    require(isFinalized);
    super.transfer(_to,_value)
}

...

```
In such cases, if a privileged user loses their private keys, or becomes inactive, the entire token contract becomes inoperable. In this case, if the `owner` cannot call `finalize()` no tokens can be transferred; i.e. the entire operation of the token ecosystem hinges on a single address.

**4. Progressing state based on external calls** - Contracts are sometimes written such that in order to progress to a new state
requires sending ether to an address, or waiting for some input from an
external source.  These patterns can lead to DOS attacks, when the external
call fails or is prevented for external reasons. In the example of sending
ether, a user can create a contract which does not accept ether. If a contract
requires ether to be withdrawn (consider a time-locking contract that requires all
    ether to be withdrawn before being useable again) in order to progress to a new state, the
contract will never achieve the new state as ether can never be sent to the
user's contract which does not accept ether.

<h3 id="dos-prev">Preventative Techniques</h3>

In the first example, contracts should not loop through data structures that can be artificially manipulated by external users. A withdrawal pattern is recommended, whereby each of the investors call a withdraw function to claim tokens independently.

In the second example a privileged user was required to change the state of the contract. In such examples (wherever possible) a fail-safe can be used in the event that the `owner` becomes incapacitated. One solution could be setting up the `owner` as a multisig contract. Another solution is to use a timelock, where the require on line \[13\] could include a time-based mechanism, such as `require(msg.sender == owner || now > unlockTime)` which allows any user to finalise after a period of time, specified by `unlockTime`. This kind of mitigation technique can be used in the third example also. If external calls are required to progress to a new state, account for their possible failure and potentially add a time-based state progression in the event that the desired call never comes.

*Note: Of course there are centralised alternatives to these suggestions where one can add a `maintenanceUser` who can come along and fix problems with DOS-based attack vectors if need be. Typically these kinds of contracts contain trust issues over the power of such an entity, but that is not a conversation for this section.*

<h3 id="dos-example">Real-World Examples: GovernMental </h3>

[GovernMental](http://governmental.github.io/GovernMental/) was an old Ponzi scheme that accumulated quite a large amount of ether. In fact, at one point it had accumulated 1100 ether. Unfortunately, it was susceptible to the DOS vulnerabilities mentioned in this section. [This Reddit Post](https://www.reddit.com/r/ethereum/comments/4ghzhv/governmentals_1100_eth_jackpot_payout_is_stuck/) describes how the contract required the deletion of a large mapping in order to withdraw the ether. The deletion of this mapping had a gas cost that exceeded the block gas limit at the time, and thus was not possible to withdraw the 1100 ether. The contract address is [0xF45717552f12Ef7cb65e95476F217Ea008167Ae3](https://etherscan.io/address/0xf45717552f12ef7cb65e95476f217ea008167ae3) and you can see from transaction [0x0d80d67202bd9cb6773df8dd2020e7190a1b0793e8ec4fc105257e8128f0506b](https://etherscan.io/tx/0x0d80d67202bd9cb6773df8dd2020e7190a1b0793e8ec4fc105257e8128f0506b) that the 1100 ether was finally obtained with a transaction that used 2.5M gas (after the block gas limit allowed such a transaction).


<h2 id="block-timestamp"><span id="SP-12">12. Block Timestamp Manipulation</span></h2>

Block timestamps have historically been used for a variety of applications, such as entropy for random numbers (see the [Entropy Illusion](#entropy) section for further details), locking funds for periods of time and various state-changing conditional statements that are time-dependent. Miner's have the ability to adjust timestamps slightly which can prove to be quite dangerous if block timestamps are used incorrectly in smart contracts.

Some useful references for this are: [The Solidity Docs](http://solidity.readthedocs.io/en/latest/units-and-global-variables.html#block-and-transaction-properties), this [Stack Exchange Question](https://ethereum.stackexchange.com/questions/413/can-a-contract-safely-rely-on-block-timestamp?utm_medium=organic&utm_source=google_rich_qa&utm_campaign=google_rich_qa).


<h3 id="block-timestamp-vuln">The Vulnerability</h3>

`block.timestamp` or its alias `now` can be manipulated by miners if they have some incentive to do so. Let's construct a simple game, which would be vulnerable to miner exploitation,

`roulette.sol`:
```solidity
contract Roulette {
    uint public pastBlockTime; // Forces one bet per block

    constructor() public payable {} // initially fund contract

    // fallback function used to make a bet
    function () public payable {
        require(msg.value == 10 ether); // must send 10 ether to play
        require(now != pastBlockTime); // only 1 transaction per block
        pastBlockTime = now;
        if(now % 15 == 0) { // winner
            msg.sender.transfer(this.balance);
        }
    }
}
```

This contract behaves like a simple lottery. One transaction per block can bet `10 ether` for a chance to win the balance of the contract. The assumption here is that, `block.timestamp` is uniformly distributed about the last two digits. If that were the case, there would be a 1/15 chance of winning this lottery.

However, as we know, miners can adjust the timestamp, should they need to.  In this particular case, if enough ether pooled in the contract, a miner who solves a block is incentivised to choose a timestamp such that `block.timestamp` or `now` modulo 15 is `0`. In doing so they may win the ether locked in this contract along with the block reward. As there is only one person allowed to bet per block, this is also vulnerable to [front-running](#race-conditions) attacks.

In practice, block timestamps are monotonically increasing and so miners cannot choose arbitrary block timestamps (they must be larger than their predecessors). They are also limited to setting blocktimes not too far in the future as these blocks will likely be rejected by the network (nodes will not validate blocks whose timestamps are in the future).

<h3 id="block-timestamp-prev">Preventative Techniques</h3>

Block timestamps should not be used for entropy or generating random numbers - i.e. they should not be the deciding factor (either directly or through some derivation) for winning a game or changing an important state (if assumed to be random).

Time-sensitive logic is sometimes required; i.e. unlocking contracts (timelocking), completing an ICO after a few weeks or enforcing expiry dates. It is sometimes recommend to use `block.number` (see the [Solidity docs](http://solidity.readthedocs.io/en/latest/units-and-global-variables.html#block-and-transaction-properties)) and an average block time to estimate times; .i.e. `1 week` with a `10 second` block time, equates to approximately, `60480 blocks`. Thus, specifying a block number at which to change a contract state can be more secure as miners are unable to manipulate the block number as easily. The [BAT ICO](https://etherscan.io/address/0x0d8775f648430679a709e98d2b0cb6250d2887ef#code) contract employed this strategy.

This can be unnecessary if contracts aren't particularly concerned with miner manipulations of the block timestamp, but it is something to be aware of when developing contracts.

<h3 id="block-timestamp-example">Real-World Example: GovernMental </h3>

[GovernMental](http://governmental.github.io/GovernMental/) was an old Ponzi scheme that accumulated quite a large amount of ether. It was also vulnerable to a timestamp-based attack. The contract payed out to the player who was the last player to join (for at least one minute) in a round. Thus, a miner who was a player, could adjust the timestamp (to a future time, to make it look like a minute had elapsed) to make it appear that the player was the last to join for over a minute (even though this is not true in reality). More detail on this can be found in the [History of Ethereum Security Vulnerabilities Post](https://applicature.com/blog/history-of-ethereum-security-vulnerabilities-hacks-and-their-fixes) by Tanya Bahrynovska.

<h2 id="constructors"><span id="SP-13">13. Constructors with Care</span></h2>

Constructors are special functions which often perform critical, privileged tasks when initialising contracts. Before solidity `v0.4.22` constructors were defined as functions that had the same name as the contract that contained them. Thus, when a contract name gets changed in development, if the constructor name isn't changed, it becomes a normal, callable function. As you can imagine, this can (and has) lead to some interesting contract hacks.

For further reading, I suggest the reader attempt the [Ethernaught Challenges](https://github.com/OpenZeppelin/ethernaut) (in particular the Fallout level).

<h3 id="constructors-vuln">The Vulnerability</h3>

If the contract name gets modified, or there is a typo in the constructor's name such that it no longer matches the name of the contract, the constructor will behave like a normal function. This can lead to dire consequences, especially if the constructor is performing privileged operations. Consider the following contract

```solidity
contract OwnerWallet {
    address public owner;

    //constructor
    function ownerWallet(address _owner) public {
        owner = _owner;
    }

    // fallback. Collect ether.
    function () payable {}

    function withdraw() public {
        require(msg.sender == owner);
        msg.sender.transfer(this.balance);
    }
}
```

This contract collects ether and only allows the owner to withdraw all the ether by calling the `withdraw()` function. The issue arises due to the fact that the constructor is not exactly named after the contract. Specifically, `ownerWallet` is not the same as `OwnerWallet`. Thus, any user can call the `ownerWallet()` function, set themselves as the owner and then take all the ether in the contract by calling `withdraw()`.


<h3 id="constructors-prev">Preventative Techniques</h3>

This issue has been primarily addressed in the Solidity compiler in version `0.4.22`. This version introduced a `constructor` keyword which specifies the constructor, rather than requiring the name of the function to match the contract name. Using this keyword to specify constructors is recommended to prevent naming issues as highlighted above.

<h3 id="constructors-example">Real-World Example: Rubixi</h3>

Rubixi ([contract code](https://etherscan.io/address/0xe82719202e5965Cf5D9B6673B7503a3b92DE20be#code)) was another pyramid scheme that exhibited this kind of vulnerability. It was originally called `DynamicPyramid` but the contract name was changed before deployment to `Rubixi`. The constructor's name wasn't changed, allowing any user to become the `creator`. Some interesting discussion related to this bug can be found on this [Bitcoin Thread](https://bitcointalk.org/index.php?topic=1400536.60). Ultimately, it allowed users to fight for `creator` status to claim the fees from the pyramid scheme. More detail on this particular bug can be found [here](https://applicature.com/blog/history-of-ethereum-security-vulnerabilities-hacks-and-their-fixes).


<h2 id="storage"><span id="SP-14">14. Uninitialised Storage Pointers</span></h2>

The EVM stores data either as `storage` or as `memory`. Understanding exactly how this is done and the default types for local variables of functions is highly recommended when developing contracts. This is because it is possible to produce vulnerable contracts by inappropriately initialising variables.

To read more about `storage` and `memory` in the EVM, see the [Solidity Docs: Data Location](http://solidity.readthedocs.io/en/latest/types.html#data-location), [Solidity Docs: Layout of State Variables in Storage](http://solidity.readthedocs.io/en/latest/miscellaneous.html#layout-of-state-variables-in-storage), [Solidity Docs: Layout in Memory](http://solidity.readthedocs.io/en/latest/miscellaneous.html#layout-in-memory).

*This section is based off the excellent [post by Stefan Beyer](https://medium.com/cryptronics/storage-allocation-exploits-in-ethereum-smart-contracts-16c2aa312743). Further reading on this topic can be found from Sefan's inspiration, which is this [reddit thread](https://www.reddit.com/r/ethdev/comments/7wp363/how_does_this_honeypot_work_it_seems_like_a/).*

<h3 id="storage-vuln">The Vulnerability</h3>

Local variables within functions default to `storage` or `memory` depending on their type. Uninitialised local `storage` variables can point to other unexpected storage variables in the contract, leading to intentional (i.e. the developer intentionally puts them there to attack later) or unintentional vulnerabilities.

Let's consider the following, relatively simple name registrar contract:

```solidity
// A Locked Name Registrar
contract NameRegistrar {

    bool public unlocked = false;  // registrar locked, no name updates

    struct NameRecord { // map hashes to addresses
        bytes32 name;
        address mappedAddress;
    }

    mapping(address => NameRecord) public registeredNameRecord; // records who registered names
    mapping(bytes32 => address) public resolve; // resolves hashes to addresses

    function register(bytes32 _name, address _mappedAddress) public {
        // set up the new NameRecord
        NameRecord newRecord;
        newRecord.name = _name;
        newRecord.mappedAddress = _mappedAddress;

        resolve[_name] = _mappedAddress;
        registeredNameRecord[msg.sender] = newRecord;

        require(unlocked); // only allow registrations if contract is unlocked
    }
}

```

This simple name registrar has only one function. When the contract is `unlocked`, it allows anyone to register a name (as a `bytes32` hash) and map that name to an address. Unfortunately, this registrar is initially locked and the `require` on line \[23\] prevents `register()` from adding name records. There is however a vulnerability in this contract, that allows name registration regardless of the `unlocked` variable.

To discuss this vulnerability, first we need to understand how storage works in Solidity. As a high level overview (without any proper technical detail -  I suggest reading the Solidity docs for a proper review), state variables are stored sequentially in *slots* as they appear in the contract (they can be grouped together, but not in this example, so we won't worry about that). Thus, `unlocked` exists in `slot 0`, `registeredNameRecord` exists in `slot 1` and `resolve` in `slot 2` etc. Each of these slots are of byte size 32 (there are added complexities with mappings which we ignore for now). The boolean `unlocked` will look like `0x000...0` (64 `0`'s, excluding the `0x`) for `false` or `0x000...1`(63 `0`'s) for `true`. As you can see, there is a significant waste of storage in this particular example.

The next piece of information that we need, is that Solidity defaults complex data types, such as `structs`, to `storage` when initialising them as local variables. Therefore, `newRecord` on line \[16\] defaults to `storage`. The vulnerability is caused by the fact that `newRecord` is not initialised. Because it defaults to storage, it becomes a pointer to storage and because it is uninitialised, it points to slot `0` (i.e. where `unlocked` is stored). Notice that on lines \[17\] and \[18\] we then set `nameRecord.name` to `_name` and `nameRecord.mappedAddress` to `_mappedAddress`, this in effect changes the storage location of slot 0 and slot 1 which modifies both `unlocked` and the storage slot associated with `registeredNameRecord`.

This means that `unlocked` can be directly modified, simply by the `bytes32 _name` parameter of the `register()` function. Therefore, if the last byte  of `_name` is non-zero, it will modify the last byte of storage `slot 0` and directly change `unlocked` to `true`. Such `_name` values will pass the `require()` on line \[23\] as we are setting `unlocked` to `true`. Try this in Remix. Notice the function will pass if you use a `_name` of the form: `0x0000000000000000000000000000000000000000000000000000000000000001`

<h3 id="storage-prev">Preventative Techniques</h3>

The Solidity compiler raises uninitialised storage variables as warnings, thus developers should pay careful attention to these warnings when building smart contracts. The current version of mist (0.10), doesn't allow these contracts to be compiled. It is good practice to explicitly use the `memory` or `storage` keywords when dealing with complex types to ensure they behave as expected. As of Solidity version `0.5.0` use of `memory` and `storage` are mandatory.

<h3 id="storage-example">Real-World Examples: Honey Pots: OpenAddressLottery and CryptoRoulette</h3>

A honey pot named OpenAddressLottery ([contract code](https://etherscan.io/address/0x741f1923974464efd0aa70e77800ba5d9ed18902#code)) was deployed that used this uninitialised storage variable querk to collect ether from some would-be hackers. The contract is rather in-depth, so I will leave the discussion to this [reddit thread](https://www.reddit.com/r/ethdev/comments/7wp363/how_does_this_honeypot_work_it_seems_like_a/) where the attack is quite clearly explained.

Another honey pot, CryptoRoulette ([contract code](https://etherscan.io/address/0x8685631276cfcf17a973d92f6dc11645e5158c0c#code)) also utilises this trick to try and collect some ether. If you can't figure out how the attack works, see [An analysis of a couple Ethereum honeypot contracts](https://medium.com/@jsanjuas/an-analysis-of-a-couple-ethereum-honeypot-contracts-5c07c95b0a8d) for an overview of this contract and others.


<h2 id="precision"><span id="SP-15">15. Floating Points and Precision</span></h2>

As of this writing (Solidity v0.4.24), fixed point or floating point numbers are not supported. This means that floating point representations must be made with the integer types in Solidity. This can lead to errors/vulnerabilities if not implemented correctly.

For further reading, see [Ethereum Contract Security Techniques and Tips - Rounding with Integer Division](https://github.com/ethereum/wiki/wiki/Safety#beware-rounding-with-integer-division),

<h3 id="precision-vuln">The Vulnerability</h3>

As there is no fixed point type in Solidity, developers are required to implement their own using the standard integer data types. There are a number of pitfalls developers can run into during this process. I will try to highlight some of these in this section.

Let's begin with a code example (let's ignore any over/under flow issues for simplicity).

```solidity
contract FunWithNumbers {
    uint constant public tokensPerEth = 10;
    uint constant public weiPerEth = 1e18;
    mapping(address => uint) public balances;

    function buyTokens() public payable {
        uint tokens = msg.value/weiPerEth*tokensPerEth; // convert wei to eth, then multiply by token rate
        balances[msg.sender] += tokens;
    }

    function sellTokens(uint tokens) public {
        require(balances[msg.sender] >= tokens);
        uint eth = tokens/tokensPerEth;
        balances[msg.sender] -= tokens;
        msg.sender.transfer(eth*weiPerEth); //
    }
}
```

This simple token buying/selling contract has some obvious problems in the buying and selling of tokens. Although the mathematical calculations for buying and selling tokens are correct, the lack of floating point numbers will give erroneous results. For example, when buying tokens on line \[7\], if the value is less than `1 ether` the initial division will result in `0`, leaving the final multiplication `0` (i.e. `200 wei` divided by `1e18` `weiPerEth` equals `0`). Similarly, when selling tokens, any tokens less than `10` will also result in `0 ether`. In fact, rounding here is always down, so selling `29 tokens`, will result in `2 ether`.

The issue with this contract is that the precision is only to the nearest `ether` (i.e. `1e18 wei`). This can sometimes get tricky when dealing with `decimals` in [ERC20](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md) tokens when you need higher precisions.

<h3 id="precision-prev">Preventative Techniques</h3>

Keeping the right precision in your smart contracts is very important, especially when dealing ratios and rates which reflect economic decisions.

You should ensure that any ratios or rates you are using allow for large numerators in fractions. For example, we used the rate `tokensPerEth` in our example. It would have been better to use `weiPerTokens` which would be a large number. To solve for the amount of tokens we could do `msg.value/weiPerTokens`. This would give a more precise result.

Another tactic to keep in mind, is to be mindful of order of operations. In the above example, the calculation to purchase tokens was `msg.value/weiPerEth*tokenPerEth`. Notice that the division occurs before the multiplication. This example would have achieved a greater precision if the calculation performed the multiplication first and then the division, i.e. `msg.value*tokenPerEth/weiPerEth`.

Finally, when defining arbitrary precision for numbers it can be a good idea to convert variables into higher precision, perform all mathematical operations, then finally when needed, convert back down to the precision for output. Typically `uint256`'s are used (as they are optimal for gas usage) which give approximately 60 orders of magnitude in their range, some of which can be dedicated to the precision of mathematical operations. It may be the case that it is better to keep all variables in high precision in solidity and convert back to lower precisions in external apps (this is essentially how the `decimals` variable works in [ERC20 Token](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md) contracts). To see examples of how this can be done and the libraries to do this, I recommend looking at the [Maker DAO DSMath](https://github.com/dapphub/ds-math). They use some funky naming, `WAD`s and `RAY`s but the concept is useful.

<h3 id="precision-example">Real-World Example: Ethstick</h3>

I couldn't find a good example where rounding has caused a severe issue in a contract, but I'm sure there are plenty out there. Feel free to update this if you have a good one in mind.

For lack of a good example, I want to draw your attention to [Ethstick](https://etherscan.io/address/0xbA6284cA128d72B25f1353FadD06Aa145D9095Af#code) mainly because I like the cool naming within the contract. This contract doesn't use any extended precision, however, it deals with `wei`. So this contract will have issues of rounding, but only at the `wei` level of precision. It has some more serious flaws, but these are relating back to the difficulty in getting entropy on the blockchain (see [Entropy Illusion](#entropy-illusion)). For a further discussion on the Ethstick contract, I'll refer you to another post of Peter Venesses, [Ethereum Contracts Are Going to be Candy For Hackers](https://vessenes.com/ethereum-contracts-are-going-to-be-candy-for-hackers/).


<h2 id="tx-origin"><span id="SP-16">16. Tx.Origin Authentication<span></h2>

Solidity has a global variable, `tx.origin` which traverses the entire call stack and returns the address of the account that originally sent the call (or transaction). Using this variable for authentication in smart contracts leaves the contract vulnerable to a phishing-like attack.

For further reading, see [Stack Exchange Question](https://ethereum.stackexchange.com/questions/1891/whats-the-difference-between-msg-sender-and-tx-origin), [Peter Venesses's Blog](https://vessenes.com/tx-origin-and-ethereum-oh-my/) and [Solidity - Tx.Origin attacks](https://medium.com/coinmonks/solidity-tx-origin-attacks-58211ad95514).

<h3 id="tx-origin-vuln">The Vulnerability</h3>

Contracts that authorise users using the `tx.origin` variable are typically vulnerable to phishing attacks which can trick users into performing authenticated actions on the vulnerable contract.

Consider the simple contract,

```solidity
contract Phishable {
    address public owner;

    constructor (address _owner) {
        owner = _owner;
    }

    function () public payable {} // collect ether

    function withdrawAll(address _recipient) public {
        require(tx.origin == owner);
        _recipient.transfer(this.balance);
    }
}
```

Notice that on line \[11\] this contract authorises the `withdrawAll()` function using `tx.origin`. This contract allows for an attacker to create an attacking contract of the form,

```solidity
import "Phishable.sol";

contract AttackContract {

    Phishable phishableContract;
    address attacker; // The attackers address to receive funds.

    constructor (Phishable _phishableContract, address _attackerAddress) {
        phishableContract = _phishableContract;
        attacker = _attackerAddress;
    }

    function () payable {
        phishableContract.withdrawAll(attacker);
    }
}
```
To utilise this contract, an attacker would deploy it, and then convince the owner of the `Phishable` contract to send this contract some amount of ether. The attacker may disguise this contract as their own private address and social engineer the victim to send some form of transaction to the address. The victim, unless being careful, may not notice that there is code at the attacker's address, or the attacker may pass it off as being a multisignature wallet or some advanced storage wallet (remember
source code of public contracts is not available by default).

In any case, if the victim sends a transaction (with enough gas) to the `AttackContract` address, it will invoke the fallback function, which in turn calls the `withdrawAll()` function of the `Phishable` contract, with the parameter `attacker`. This will result in the withdrawal of all funds from the `Phishable` contract to the `attacker` address. This is because the address that first initialised the call was the victim (i.e. the `owner` of the `Phishable` contract). Therefore, `tx.origin` will be equal to `owner` and the `require` on line \[11\] of the `Phishable` contract will pass.

<h3 id="tx-origin-prev">Preventative Techniques</h3>

`tx.origin` should not be used for authorisation in smart contracts. This isn't to say that the `tx.origin` variable should never be used. It does have some legitimate use cases in smart contracts. For example, if one wanted to deny external contracts from calling the current contract, they could implement a `require` of the from `require(tx.origin == msg.sender)`. This prevents intermediate contracts being used to call the current contract, limiting the contract to regular code-less addresses.

<h3 id="tx-origin-example">Real-World Example: Not Known</h3>

I do not know of any publicised exploits of this form in the wild.

<h2 id="ethereum-quirks">Ethereum Quirks</h2>

I intend to populate this section with various interesting quirks that get discovered by the community. These are kept in this blog as they may aid in smart contract development if one were to utilize these quirks in practice.

<h3 id="keyless-eth">Keyless Ether</h3>

Contract addresses are deterministic, meaning that they can be calculated prior to actually creating the address. This is the case for addresses creating contracts and also for contracts spawning other  contracts. In fact, a created contract's address is determined by:

`keccak256(rlp.encode([<account_address>, <transaction_nonce>])`

Essentially, a contract's address is just the `keccak256` hash of the account that created it concatenated with the accounts transaction nonce[^2]. The same is true for contracts, except contracts nonce's start at `1` whereas address's transaction nonce's start at `0`.

This means that given an Ethereum address, we can calculate all the possible contract addresses that this address can spawn. For example, if the address `0x123000...000` were to create a contract on its 100th transaction, it would create the contract address `keccak256(rlp.encode[0x123...000, 100])`, which would give the contract address, `0xed4cafc88a13f5d58a163e61591b9385b6fe6d1a`.

What does this all mean? This means that you can send ether to a pre-determined address (one which you don't own the private key to, but know that one of your accounts can create a contract to). You can send ether to that address and then retrieve the ether by later creating a contract which gets spawned over the same address. The constructor could be used to return all your pre-sent ether. Thus if someone were to obtain all your Ethereum private keys, it would be difficult for the attacker to discover that your Ethereum addresses also have access to this *hidden* ether. In fact, if the attacker spent too many transaction such that the nonce required to access your ether is used, it is impossible to recover your hidden ether.

Let me clarify this with a contract.

```solidity
contract KeylessHiddenEthCreator {
    uint public currentContractNonce = 1; // keep track of this contracts nonce publicly (it's also found in the contracts state)

    // determine future addresses which can hide ether.
    function futureAddresses(uint8 nonce) public view returns (address) {
        if(nonce == 0) {
            return address(keccak256(0xd6, 0x94, this, 0x80));
        }
        return address(keccak256(0xd6, 0x94, this, nonce));
    // need to implement rlp encoding properly for a full range of nonces
    }

    // increment the contract nonce or retrieve ether from a hidden/key-less account
    // provided the nonce is correct
    function retrieveHiddenEther(address beneficiary) public returns (address) {
        currentContractNonce +=1;
        return new RecoverContract(beneficiary);
    }

    function () payable {} // Allow ether transfers (helps for playing in remix)
}

contract RecoverContract {
    constructor(address beneficiary) {
        selfdestruct(beneficiary); // don't deploy code. Return the ether stored here to the beneficiary.
    }
 }
```
This contract allows you to store keyless ether (relatively safely, in the sense you can't accidentally miss the nonce)[^3]. The `futureAddresses()` function can be used to calculate the first 127 contract addresses that this contract can spawn, by specifying the `nonce`. If you send ether to one of these addresses, it can be later recovered by calling the `retrieveHiddenEther()` enough times. For example, if you choose `nonce=4` (and send ether to the associated address), you will need to call `retrieveHiddenEther()` four times and it will recover the ether to the `beneficiary` address.

This can be done without a contract. You can send ether to addresses that can be created from one of your standard Ethereum accounts and recover it later, at the correct nonce. Be careful however, if you accidentally surpass the transaction nonce that is required to recover your ether, your funds will be lost forever.

 For more information on some more advanced tricks you can do with this quirk, I recommend reading [Martin Swende's post](http://martin.swende.se/blog/Ethereum_quirks_and_vulns.html).


<h3 id="one-time-addresses">One Time Addresses</h3>

Ethereum transaction signing uses the Elliptic Curve Digital Signing Algorithm (ECDSA). Conventionally, in order to send a verified transaction on Ethereum, you sign a message with your Ethereum private key, which authorises spending from your account. In slightly more detail, the message that you sign is the components of the Ethereum transaction, specifically, the `to`, `value`, `gas`, `gasPrice`, `nonce` and `data` fields. The result of an Ethereum signature is three numbers, `v`, `r` and `s`. I won't go into detail about what each of these represent, instead I refer the interested readers to the [ECDSA wiki page](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) (which describes `r` and `s`) and the [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf) (Appendix F - which describes `v`) and finally [EIP155](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md) for the current use of `v`.

So we know that an Ethereum transaction signature consists of a message and the numbers `v`, `r` and `s`. We can check if a signature is valid, by using the message (i.e. transaction details), `r` and `s` to derive an Ethereum address. If the derived Ethereum address matches the `from` field of the transaction, then we know that `r` and `s` were created by someone who owns (or has access to) the private key for the `from` field and thus the signature is valid.

Consider now, that we don't own a private key, but instead make up values for `r` and `s` for an arbitrary transaction. Consider we have a transaction, with the parameters:

```javascript
{to: "0xa9e", value: 10e18, nonce: 0}
```

I've ignored the other parameters. This transaction will send 10 ether to the `0xa9e` address. Now let's say we make up some numbers `r` and `s` (these have specific ranges) and a `v`. If we derive the Ethereum address related to these made up numbers we will get a random Ethereum address, let's call it `0x54321`. Knowing this address, we could send 10 ether to the `0x54321` address (without owning the private key for the address). At any point in the future, we could send the transaction,
```javascript
{to: "0xa9e", value: 10e18, nonce: 0, from: "0x54321"}
```
along with the signature, i.e. the `v`, `r` and `s` we made up. This will be a valid transaction, because the derived address will match our `from` field. This allows us to spend our money from this random address (`0x54321`) to the address we chose `0xa9e`. Thus we have managed to store ether in an address that we do not have the private key and used a one-time transaction to recover the ether.

This quirk can also be used to send ether to a large number of people in a trustless manner, as Nick Johnson describes in [How to send Ether to 11,440 people](https://medium.com/@weka/how-to-send-ether-to-11-440-people-187e332566b7).

<h3 id="single-transaction-airdrops">Single Transaction Airdrops</h3>

An Airdrop refers to the process of distributing tokens amongst a large
group of people. Traditionally, airdrops have been processed via a large number
of transactions where each transaction updates either a single or a batch of
user's balances. This can be costly and strenuous on the Ethereum blockchain.
There is an alternative method, in which many users balances can be credited
with tokens using a single transaction.

This technique is explained in more detail by its proposer, RicMoo in his post:
[Merkle Air-Drops: Make Love, Not War](https://blog.ricmoo.com/merkle-air-drops-e6406945584d).

The idea is to create a [Merkle Tree](https://en.wikipedia.org/wiki/Merkle_tree)
which contains (as leaf nodes) all the addresses and balances of users to be credited tokens.
This will be done off-chain. The merkle tree can be given out
publicly (again off-chain). A smart contract can then be created containing the
root hash of the merkle tree which allows users to submit [merkle-proofs](https://www.quora.com/Cryptography-How-does-a-Merkle-proof-actually-work) to obtain
their tokens. Thus a single transaction (the one used to create the contract,
    or to simply store the Merkle tree root hash), allows all credited users to redeem
their airdropped tokens.

RicMoo in his [post](https://blog.ricmoo.com/merkle-air-drops-e6406945584d) also provides an example of a function which can accept Merkle Proofs
and credit a user's balance:
```solidity
function redeem(uint256 index, address recipient,
                uint256 amount, bytes32[] merkleProof) public {

    // Make sure this has not been redeemed
    uint256 redeemedBlock = _redeemed[index / 256];
    uint256 redeemedMask = (uint256(1) << uint256(index % 256));
    require((redeemedBlock & redeemedMask) == 0);

    // Mark it as redeemed (if we fail, we revert)
    _redeemed[index / 256] = redeemedBlock | redeemedMask;

    // Compute the merkle root from the merkle proof
    bytes32 node = keccak256(index, recipient, amount);
    uint256 path = index;
    for (uint16 i = 0; i < merkleProof.length; i++) {
        if ((path & 0x01) == 1) {
            node = keccak256(merkleProof[i], node);
        } else {
            node = keccak256(node, merkleProof[i]);
        }
        path /= 2;
    }

    // Check the resolved merkle proof matches our merkle root
    require(node == _rootHash);

    // Redeem!
    _balances[recipient] += amount;
    _totalSupply += amount;
    Transfer(0, recipient, amount);
}
```
This function could be built into a token contract to allow future airdrops.
The only transaction required to credit all user's balances, would be the
transaction that sets the Merkle tree root.


<h2 id="hacks">List of Interesting Crypto Related Hacks/Bugs</h2>

* [SpankChain](https://medium.com/spankchain/we-got-spanked-what-we-know-so-far-d5ed3a0f38fe)
* [CoinDash](https://www.theregister.co.uk/2017/07/18/coindash_hack/)
* [SmartBillions](https://www.reddit.com/r/ethereum/comments/74d3dc/smartbillions_lottery_contract_just_got_hacked/)
* [Exchange Didn't add "0x" to payload](https://steemit.com/cryptocurrency/@barrydutton/breaking-the-biggest-canadian-coin-exchange-quadrigacx-loses-67-000-usdeth-due-to-coding-error-funds-locked-in-an-executable)


[^1]: This code was modified from [web3j](https://github.com/web3j/web3j/blob/master/codegen/src/test/resources/solidity/fibonacci/Fibonacci.sol)

[^2]: A transaction nonce is like a transaction counter. It increments ever time a transaction is sent from your account.

[^3]: Do not deploy this contract to store any real ether. It is for demonstrative purposes only. It has no inherent privileges, anyone can recover your ether if you deploy and use it.
