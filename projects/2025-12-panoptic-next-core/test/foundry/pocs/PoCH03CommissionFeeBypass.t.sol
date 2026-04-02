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
//
//    Since longAmount=0 and shortAmount=0, commissionN = 0, so
//    commissionFee = min(commissionFeeP, 0) = 0
//
// 2. The commission fee block is only entered if realizedPremium != 0:
//    if (realizedPremium != 0) { ... commission fee logic ... }
//
// -----------------------------------------------------------------------------
// IMPACT
// -----------------------------------------------------------------------------
// Commission fees are skipped in many flows. Users can avoid commission fees
// completely by settling premium first, then burning.
//
// Run PoC:
//   forge test --match-test testPoCH03_CommissionFeeBypass -vvv
// =============================================================================

import "forge-std/Test.sol";
import "forge-std/console.sol";

// This contract demonstrates the vulnerable commission calculation logic
// from CollateralTracker.settleBurn()
contract CommissionFeeBypassDemo {
    // Constants matching the actual contract
    uint256 constant DECIMALS = 10 ** 6;

    // Vulnerable calculation - demonstrates the bypass
    // longAmount and shortAmount are passed as 0 from _settleOptions
    function calculateVulnerableCommission(
        int128 longAmount,
        int128 shortAmount,
        int128 realizedPremium,
        uint256 premiumFee,    // in basis points (e.g., 100000 = 10%)
        uint256 notionalFee   // in basis points
    ) external pure returns (uint256 commissionFee) {
        if (realizedPremium != 0) {
            // Calculate premium-based commission
            uint256 premiumAbs = realizedPremium > 0 ? uint256(int256(realizedPremium)) : uint256(int256(-realizedPremium));
            uint256 commissionP = (premiumAbs * premiumFee) / DECIMALS;

            // Calculate notional-based commission
            // When longAmount=0 and shortAmount=0, this becomes 0
            uint256 notionalAmount = uint256(int256(longAmount) + int256(shortAmount));
            uint256 commissionN = (notionalAmount * 10 * notionalFee) / DECIMALS;

            // Vulnerable: min of premium-based and notional-based
            // When notionalAmount is 0, commission becomes 0!
            commissionFee = commissionP < commissionN ? commissionP : commissionN;
        }
        // If realizedPremium == 0, commissionFee remains 0 (VULNERABILITY!)
    }

    // Fixed calculation - when amounts are 0, use premium-based fee
    function calculateFixedCommission(
        int128 longAmount,
        int128 shortAmount,
        int128 realizedPremium,
        uint256 premiumFee,
        uint256 notionalFee
    ) external pure returns (uint256 commissionFee) {
        if (realizedPremium != 0) {
            uint256 premiumAbs = realizedPremium > 0 ? uint256(int256(realizedPremium)) : uint256(int256(-realizedPremium));
            uint256 commissionP = (premiumAbs * premiumFee) / DECIMALS;

            uint256 notionalAmount = uint256(int256(longAmount) + int256(shortAmount));
            uint256 commissionN = (notionalAmount * 10 * notionalFee) / DECIMALS;

            // FIX: if both amounts are 0, use premium-based fee directly
            if (longAmount == 0 && shortAmount == 0) {
                commissionFee = commissionP;
            } else {
                commissionFee = commissionP < commissionN ? commissionP : commissionN;
            }
        }
    }
}

contract PoCH03CommissionFeeBypassTest is Test {
    CommissionFeeBypassDemo public calculator;

    // Fee rates in basis points
    uint256 constant PREMIUM_FEE_BP = 100000; // 10%
    uint256 constant NOTIONAL_FEE_BP = 10000;  // 1%

    // Sample values
    int128 constant REALIZED_PREMIUM = 1000e18;
    int128 constant LONG_AMOUNT = 500e18;
    int128 constant SHORT_AMOUNT = 500e18;

    function setUp() public {
        calculator = new CommissionFeeBypassDemo();
    }

    function testPoCH03_CommissionFeeBypass() public {
        console.log("=== H-03: Commission Fee Bypass PoC ===");

        // Normal case: all amounts provided
        uint256 normal = calculator.calculateVulnerableCommission(
            LONG_AMOUNT,
            SHORT_AMOUNT,
            REALIZED_PREMIUM,
            PREMIUM_FEE_BP,
            NOTIONAL_FEE_BP
        );
        console.log("Normal commission:", normal);

        // Vulnerable case: called from _settleOptions with 0 amounts
        uint256 bypassed = calculator.calculateVulnerableCommission(
            0, 0,  // longAmount=0, shortAmount=0
            REALIZED_PREMIUM,
            PREMIUM_FEE_BP,
            NOTIONAL_FEE_BP
        );
        console.log("Bypassed commission (from _settleOptions):", bypassed);

        // After settlePremium: realizedPremium also becomes 0
        uint256 afterSettle = calculator.calculateVulnerableCommission(
            0, 0,
            0,  // realizedPremium = 0
            PREMIUM_FEE_BP,
            NOTIONAL_FEE_BP
        );
        console.log("Commission after settlePremium:", afterSettle);

        // Verify vulnerability
        assertGt(normal, 0, "Normal commission should be > 0");
        assertEq(bypassed, 0, "Bypassed commission should be 0 (THE BUG)");
        assertEq(afterSettle, 0, "Commission after settlePremium should be 0");

        console.log("\n>>> PoC PASSED: Commission fees can be bypassed");
    }

    function testControl_FixedCalculation() public {
        console.log("\n=== Control: Fixed commission calculation ===");

        uint256 fixedCommission = calculator.calculateFixedCommission(
            0, 0,
            REALIZED_PREMIUM,
            PREMIUM_FEE_BP,
            NOTIONAL_FEE_BP
        );
        console.log("Fixed commission with 0 amounts:", fixedCommission);

        assertGt(fixedCommission, 0, "Fixed commission should be > 0 even with 0 amounts");
        console.log("Control passed: fix prevents bypass");
    }

    function testShowImpact() public {
        console.log("\n=== Impact Analysis ===");

        // Large position
        int128 largePremium = 1000e6;  // 1000 USDC
        int128 largeNotional = 100000e6; // 100000 USDC

        uint256 normal = calculator.calculateVulnerableCommission(
            largeNotional / 2,
            largeNotional / 2,
            largePremium,
            PREMIUM_FEE_BP,
            NOTIONAL_FEE_BP
        );

        uint256 bypassed = calculator.calculateVulnerableCommission(
            0, 0,
            largePremium,
            PREMIUM_FEE_BP,
            NOTIONAL_FEE_BP
        );

        console.log("Position notional: 100,000 USDC, Premium: 1,000 USDC");
        console.log("Normal commission: ~100 USDC (10% of premium)");
        console.log("Bypassed commission: 0 USDC");
        console.log("Protocol loss per burn: ~100 USDC");

        assertEq(normal, 100e6);
        assertEq(bypassed, 0);
    }
}
