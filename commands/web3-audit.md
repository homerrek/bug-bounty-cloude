---
description: Smart contract security audit — runs through 10 bug class checklist (accounting desync, access control, incomplete path, off-by-one, oracle errors, ERC4626, reentrancy, flash loan, signature replay, proxy/upgrade). Applies pre-dive kill signals first. Generates Foundry PoC template for confirmed findings. Usage: /web3-audit <contract.sol>
---

# /web3-audit

Smart contract security audit using the 10-bug-class methodology.

> Ref: `agents/web3-auditor.md` (pre-dive assessment + audit protocol)

## Usage

```
/web3-audit VulnerableContract.sol
/web3-audit https://github.com/protocol/contracts
/web3-audit [paste contract code]
```

## Step 0: Pre-Dive Kill Signals

ALWAYS check BEFORE reading any code:

```
1. TVL < $500K → max payout too low → SKIP
2. 2+ top-tier audits (Halborn, ToB, Cyfrin, OZ) on simple protocol → SKIP
3. Protocol < 500 lines, single A→B→C flow → minimal surface → SKIP
4. min(10% × TVL, program_cap) < $10K → SKIP
```

Score: proceed only if >= 6/10
- TVL > $10M: +2 | Immunefi Critical >= $50K: +2 | No top-tier audit: +2
- < 30 days deploy: +1 | Protocol you know: +1 | Upgradeable proxies: +1

## 10-Class Audit Checklist

Run each class in order with grep commands:

**Class 1: Accounting Desync (28% of Criticals)**
```bash
grep -rn "totalSupply\|totalShares\|totalAssets\|totalDebt\|cumulativeReward" contracts/
grep -rn "\breturn\b" contracts/ -B3 | grep -B3 "if\b"
```
Check: For each early return — (1) which state vars are updated in the normal path? (2) are ALL of them also updated in the early return path? (3) if A updated but B isn't → potential desync bug.

**Class 2: Access Control (19% of Criticals)**
```bash
grep -rn "function vote\|function poke\|function reset\|function update\|function claim\|function harvest" contracts/ -A2
grep -rn "modifier\b" contracts/ -A8 | grep -B3 "if (" | grep -v "require\|revert"
grep -rn "function initialize\b" contracts/ -A3
```
Check: does EVERY sibling function in the same family have the SAME modifiers as its siblings?

**Class 3: Incomplete Code Path (17% of Criticals)**
```bash
grep -rn "safeApprove\b" contracts/
grep -rn "function deposit\|function mint\|function withdraw\|function redeem" contracts/ -A10
```
Check: deposit/withdraw — does withdraw reverse all state changes from deposit?

**Class 4: Off-By-One (22% of Highs)**
```bash
grep -rn "Period\|Epoch\|Deadline\|period\|epoch\|deadline" contracts/ -A3 | grep "[<>][^=]"
grep -rn "\.length\s*-\s*1\|i\s*<=\s*.*\.length\b" contracts/
```
Check: every `if (A > B)` — what happens when A == B?

**Class 5: Oracle / Price Manipulation**
```bash
grep -rn "latestRoundData" contracts/ -A5 | grep -v "updatedAt\|timestamp"
grep -rn "getReserves\|getAmountsOut\|slot0\b" contracts/ -A5
```

**Class 6: ERC4626 Vaults**
```bash
grep -rn "function deposit\|function mint\|function withdraw\|function redeem" contracts/ -A10
grep -rn "_decimalsOffset\|_convertToShares\|_convertToAssets" contracts/
```

**Class 7: Reentrancy**
```bash
grep -rn "\.call{value\|safeTransfer\|transfer(" contracts/ -B10
grep -rn "function withdraw\|function redeem\|function claim" contracts/ -A2 | grep -v "nonReentrant"
```

**Class 8: Flash Loan**
```bash
grep -rn "getReserves\|slot0\b\|getAmountsOut" contracts/
```

**Class 9: Signature Replay**
```bash
grep -rn "ecrecover\|ECDSA\.recover" contracts/ -B20
grep -rn "nonce\|_nonces" contracts/
```
Check: signed hash includes nonce + chainId + contract address?

**Class 10: Proxy / Upgrade**
```bash
grep -rn "function initialize\b\|_disableInitializers\|initializer" contracts/
grep -rn "delegatecall\b" contracts/ -B3
```

## Foundry PoC Template

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/Test.sol";
import "../src/VulnerableContract.sol";

contract ExploitTest is Test {
    VulnerableContract target;
    address attacker = makeAddr("attacker");

    function setUp() public {
        vm.createSelectFork("mainnet", BLOCK_NUMBER);
        target = VulnerableContract(TARGET_ADDRESS);
        deal(address(token), attacker, INITIAL_BALANCE);
    }

    function test_exploit() public {
        uint256 before = token.balanceOf(attacker);
        vm.startPrank(attacker);
        // Execute exploit
        vm.stopPrank();
        assertGt(token.balanceOf(attacker), before, "Exploit failed");
    }
}
```

Run: `forge test --match-test test_exploit -vvvv`
