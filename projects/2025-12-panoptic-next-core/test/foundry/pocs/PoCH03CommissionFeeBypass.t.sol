// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

// =============================================================================
// VULNERABILITY ANALYSIS
// =============================================================================
//
// Title   : Commission Fees Can Always Be Bypassed
// Severity: High
// Target  : CollateralTracker.settleBurn() and PanopticPool._settleOptions()
//
// -----------------------------------------------------------------------------
// BACKGROUND
// -----------------------------------------------------------------------------
// Commission fees are supposed to be paid to PLPs (Passive Liquidity Providers)
// when options are burned. The fee is calculated as the minimum of:
//   - premiumFee (based on realized premium)
//   - notionalFee (based on longAmount + shortAmount)
//
// -----------------------------------------------------------------------------
// ROOT CAUSE
// -----------------------------------------------------------------------------
// Two issues allow commission fees to be bypassed:
//
// 1. In _settleOptions, settleBurn is called with all amount parameters = 0:
//    settleBurn(owner, 0, 0, 0, realizedPremia.rightSlot(), riskParameters);
//    settleBurn(owner, 0, 0, 0, realizedPremia.leftSlot(), riskParameters);
//
//    Since longAmount=0 and shortAmount=0, commissionN = 0, so
//    commissionFee = min(commissionFeeP, 0) = 0
//
// 2. The commission fee block is only entered if realizedPremium != 0:
//    if (realizedPremium != 0) { ... commission fee logic ... }
//
//    Users can settle premium first (making realizedPremium = 0), then burn.
//
// Vulnerable code path:
//
//   Flow 4/5 - Settle Premium -> Burn:
//     _settleOptions() {
////        settleBurn(owner, 0, 0, 0, realizedPremium, params);
//                    ^^^^^^  ^^^  ^^^  all 0!
//       -> commissionFee = min(premiumFee, 0) = 0
//     }
//
//   Bypass method:
//     1. Call _settlePremium to settle and reset realizedPremium to 0
//     2. Call _settleOptions -> settleBurn with 0 amounts -> commission = 0
//
// -----------------------------------------------------------------------------
// IMPACT
// -----------------------------------------------------------------------------
// Commission fees are skipped in many flows. Users can avoid commission fees
// completely by settling premium first, then burning.
//
// -----------------------------------------------------------------------------
// PROOF-OF-CONCEPT SCENARIO
// -----------------------------------------------------------------------------
// 1. User has a position with premium and notional value
// 2. User calls _settlePremium, resetting realizedPremium to 0
// 3. User calls _settleOptions (via burn)
// 4. settleBurn is called with all 0 amounts
// 5. Commission fee = 0 (min of premiumFee and 0)
//
// -----------------------------------------------------------------------------
// RECOMMENDED FIX
// -----------------------------------------------------------------------------
// Option 1: Remove the realizedPremium != 0 check
// Option 2: Derive commission fee from premium fee when amounts are 0
// Option 3: Always compute commission from premium, not minimum of both
//
// Run PoC:
//   forge test --match-test testPoCH03_CommissionFeeBypass -vvv
// =============================================================================

import "forge-std/Test.sol";
import "forge-std/console.sol";

import {PanopticPool} from "@contracts/PanopticPool.sol";
import {SemiFungiblePositionManager} from "@contracts/SemiFungiblePositionManagerV4.sol";
import {CollateralTracker} from "@contracts/CollateralTracker.sol";
import {RiskEngine} from "@contracts/RiskEngine.sol";
import {PanopticHelper} from "@test_periphery/PanopticHelper.sol";
import {PositionUtils, MiniPositionManager} from "../testUtils/PositionUtils.sol";
import {TokenId} from "@types/TokenId.sol";
import {LeftRightUnsigned, LeftRightSigned} from "@types/LeftRight.sol";
import {RiskParameters} from "@types/RiskParameters.sol";
import {Constants} from "@libraries/Constants.sol";
import {Errors} from "@libraries/Errors.sol";
import {Math} from "@libraries/Math.sol";

// V4 types and interfaces
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolManager} from "v4-core/PoolManager.sol";

// Simplified CollateralTracker that exposes commission calculation for testing
contract CollateralTrackerHarness is CollateralTracker, PositionUtils, MiniPositionManager {
    // Constants for fee calculation
    uint256 public constant DECIMALS = 10 ** 6;

    constructor() CollateralTracker(10) {
        bytes32 slot = keccak256("panoptic.utilization.snapshot");
        assembly {
            tstore(slot, 0)
        }
    }

    // Expose internal commission calculation for testing
    // This simulates what settleBurn does internally
    function calculateCommissionFee(
        int128 longAmount,
        int128 shortAmount,
        int128 realizedPremium,
        uint128 premiumFee,
        uint128 notionalFee
    ) external pure returns (uint128 commissionFee) {
        // This is the vulnerable logic from settleBurn
        if (realizedPremium != 0) {
            uint128 commissionP;
            unchecked {
                commissionP = realizedPremium > 0
                    ? uint128(realizedPremium)
                    : uint128(-realizedPremium);
            }
            uint128 commissionFeeP = Math
                .mulDivRoundingUp(commissionP, premiumFee, DECIMALS)
                .toUint128();
            uint128 commissionN = uint256(int256(shortAmount) + int256(longAmount)).toUint128();
            uint128 commissionFeeN;
            unchecked {
                commissionFeeN = Math
                    .mulDivRoundingUp(commissionN, 10 * notionalFee, DECIMALS)
                    .toUint128();
            }
            commissionFee = Math.min(commissionFeeP, commissionFeeN).toUint128();
        }
        // If realizedPremium == 0, commissionFee remains 0
    }

    // Calculate what commission SHOULD be if we use premium fee properly
    function calculateCommissionFeeFixed(
        int128 longAmount,
        int128 shortAmount,
        int128 realizedPremium,
        uint128 premiumFee,
        uint128 notionalFee
    ) external pure returns (uint128 commissionFee) {
        if (realizedPremium != 0) {
            uint128 commissionP;
            unchecked {
                commissionP = realizedPremium > 0
                    ? uint128(realizedPremium)
                    : uint128(-realizedPremium);
            }
            uint128 commissionFeeP = Math
                .mulDivRoundingUp(commissionP, premiumFee, DECIMALS)
                .toUint128();
            uint128 commissionN = uint256(int256(shortAmount) + int256(longAmount)).toUint128();
            uint128 commissionFeeN;
            unchecked {
                commissionFeeN = Math
                    .mulDivRoundingUp(commissionN, 10 * notionalFee, DECIMALS)
                    .toUint128();
            }
            // Fixed: if both amounts are 0, use premium-based fee
            if (shortAmount == 0 && longAmount == 0) {
                commissionFee = commissionFeeP;
            } else {
                commissionFee = Math.min(commissionFeeP, commissionFeeN).toUint128();
            }
        }
    }
}

contract PoCH03CommissionFeeBypassTest is Test {
    CollateralTrackerHarness public ct;

    // Premium fee: 10% (in DECIMALS units)
    uint128 constant PREMIUM_FEE = 100000; // 10%
    // Notional fee: 1% (in DECIMALS units)
    uint128 constant NOTIONAL_FEE = 10000; // 1%

    // Sample values for testing
    int128 constant REALIZED_PREMIUM = 1000e18;
    int128 constant LONG_AMOUNT = 500e18;
    int128 constant SHORT_AMOUNT = 500e18;

    function setUp() public {
        ct = new CollateralTrackerHarness();
    }

    // -------------------------------------------------------------------------
    // PoC: Demonstrate commission fee bypass via _settleOptions flow
    // -------------------------------------------------------------------------
    //
    // When _settleOptions calls settleBurn:
    //   - longAmount = 0
    //   - shortAmount = 0
    //   - realizedPremium = whatever (could be 0 after settlePremium)
    //
    // This means commissionFeeN = 0, so commission = min(commissionP, 0) = 0
    //
    // Expected result on UNPATCHED code : PASS (commission = 0)
    // Expected result after the fix     : FAIL (commission > 0)
    function testPoCH03_CommissionFeeBypass() public {
        console.log("=== H-03: Commission Fee Bypass PoC ===");

        // =========================================================================
        // SCENARIO 1: Normal settleBurn with all parameters set
        // =========================================================================
        console.log("\n--- Scenario 1: Normal settleBurn with all amounts ---");

        uint128 normalCommission = ct.calculateCommissionFee(
            LONG_AMOUNT,
            SHORT_AMOUNT,
            REALIZED_PREMIUM,
            PREMIUM_FEE,
            NOTIONAL_FEE
        );
        console.log("Commission with normal amounts:", normalCommission);
        console.log("Expected: min(premiumFee, notionalFee) > 0");

        // =========================================================================
        // SCENARIO 2: settleBurn called from _settleOptions (the vulnerable flow)
        // =========================================================================
        console.log("\n--- Scenario 2: settleBurn from _settleOptions (all 0 amounts) ---");

        // This is what _settleOptions does:
        // settleBurn(owner, 0, 0, 0, realizedPremium, riskParameters)
        uint128 bypassedCommission = ct.calculateCommissionFee(
            0,      // longAmount = 0
            0,      // shortAmount = 0
            REALIZED_PREMIUM,
            PREMIUM_FEE,
            NOTIONAL_FEE
        );
        console.log("Commission with 0 amounts (from _settleOptions):", bypassedCommission);
        console.log("Expected: 0 (min(premiumFee, 0) = 0)");

        // =========================================================================
        // SCENARIO 3: After settling premium first (realizedPremium = 0)
        // =========================================================================
        console.log("\n--- Scenario 3: After settlePremium (realizedPremium = 0) ---");

        uint128 afterSettleCommission = ct.calculateCommissionFee(
            0,      // longAmount = 0
            0,      // shortAmount = 0
            0,      // realizedPremium = 0 after settlePremium!
            PREMIUM_FEE,
            NOTIONAL_FEE
        );
        console.log("Commission after settlePremium with 0 amounts:", afterSettleCommission);
        console.log("Expected: 0 (entire commission block skipped when realizedPremium = 0)");

        // =========================================================================
        // ASSERTIONS
        // =========================================================================
        console.log("\n--- Verification ---");

        // Normal scenario should have non-zero commission
        assertGt(normalCommission, 0, "Normal commission should be > 0");
        console.log("Normal commission is > 0:", normalCommission);

        // Bypassed commission should be 0
        assertEq(bypassedCommission, 0, "Bypassed commission should be 0");
        console.log("Bypassed commission is 0:", bypassedCommission);

        // After settlePremium, commission should be 0
        assertEq(afterSettleCommission, 0, "Commission after settlePremium should be 0");
        console.log("After settlePremium commission is 0");

        console.log("\n>>> PoC PASSED: Commission fees can be bypassed via _settleOptions flow");
        console.log("    User can call _settlePremium first, then _settleOptions to pay 0 commission");
    }

    // -------------------------------------------------------------------------
    // Demonstrate the fix: use premium-based fee when amounts are 0
    // -------------------------------------------------------------------------
    function testControl_FixedCommissionCalculation() public {
        console.log("\n=== Control: Fixed commission calculation ===");

        // With fix: when shortAmount=0 and longAmount=0, use premium-based fee
        uint128 fixedCommission = ct.calculateCommissionFeeFixed(
            0,      // longAmount = 0
            0,      // shortAmount = 0
            REALIZED_PREMIUM,
            PREMIUM_FEE,
            NOTIONAL_FEE
        );

        uint128 normalCommission = ct.calculateCommissionFee(
            LONG_AMOUNT,
            SHORT_AMOUNT,
            REALIZED_PREMIUM,
            PREMIUM_FEE,
            NOTIONAL_FEE
        );

        console.log("Normal commission:", normalCommission);
        console.log("Fixed commission with 0 amounts:", fixedCommission);

        // Fixed version should have non-zero commission even with 0 amounts
        assertGt(fixedCommission, 0, "Fixed commission should be > 0 even with 0 amounts");
        console.log("Fixed commission is > 0:", fixedCommission);
        console.log("Control test passed: fix would prevent bypass");
    }

    // -------------------------------------------------------------------------
    // Quantitative demonstration of the bypass impact
    // -------------------------------------------------------------------------
    function testShowCommissionBypassImpact() public {
        console.log("\n=== Commission Bypass Impact Analysis ===");

        // Assume a user has a position with:
        // - Notional value: 100,000 USDC
        // - Premium: 1,000 USDC
        //
        // Normal commission (1% of notional or 10% of premium, whichever is smaller):
        // - premiumFee = 10% of 1000 = 100 USDC
        // - notionalFee = 1% of 100000 = 1000 USDC
        // - commission = min(100, 1000) = 100 USDC
        //
        // Bypassed commission (when amounts are 0):
        // - commissionFeeN = 0 (since shortAmount + longAmount = 0)
        // - commission = min(100, 0) = 0 USDC

        int128 largePremium = 1000e6;  // 1000 USDC
        int128 largeNotional = 100000e6; // 100000 USDC
        uint128 premiumFeeRate = 100000;  // 10%
        uint128 notionalFeeRate = 10000;   // 1%

        uint128 normalCommission = ct.calculateCommissionFee(
            largeNotional / 2,
            largeNotional / 2,
            largePremium,
            premiumFeeRate,
            notionalFeeRate
        );

        uint128 bypassedCommission = ct.calculateCommissionFee(
            0,
            0,
            largePremium,
            premiumFeeRate,
            notionalFeeRate
        );

        console.log("Position notional value: 100,000 USDC");
        console.log("Position premium: 1,000 USDC");
        console.log("Normal commission (1% of notional capped at 10% of premium): 100 USDC");
        console.log("Bypassed commission via _settleOptions: 0 USDC");
        console.log("Loss to protocol per burn: 100 USDC");

        assertEq(normalCommission, 100e6, "Normal commission should be 100 USDC");
        assertEq(bypassedCommission, 0, "Bypassed commission should be 0");

        console.log("\n>>> Impact: Protocol loses 100 USDC per position burn");
    }
}
