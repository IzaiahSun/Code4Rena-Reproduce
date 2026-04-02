// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

// =============================================================================
// VULNERABILITY ANALYSIS
// =============================================================================
//
// Title   : Order double-linked list is broken because order.prevOrderId is not persisted
// Severity: High
// Target  : Book.sol - _updateLimitPostOrder()
//
// -----------------------------------------------------------------------------
// BACKGROUND
// -----------------------------------------------------------------------------
// Orders are stored as a double-linked list in the book. When a new order is
// added to a price level, it becomes the new tail and its prevOrderId should
// point to the previous tail order.
//
// -----------------------------------------------------------------------------
// ROOT CAUSE
// -----------------------------------------------------------------------------
// In Book._updateLimitPostOrder(), the prevOrderId is set on the memory copy
// of the order rather than the storage copy:
//
//   Order storage tailOrder = self.orders[limit.tailOrder];
//   tailOrder.nextOrderId = order.id;
//   order.prevOrderId = tailOrder.id;  // <-- BUG: order is memory, not storage!
//   limit.tailOrder = order.id;
//
// Since `order` is passed as `memory` type, the prevOrderId assignment is lost
// after the function returns.
//
// -----------------------------------------------------------------------------
// IMPACT
// -----------------------------------------------------------------------------
// The double-linked list is broken. Traversal via prevOrderId fails because
// the value was never written to storage. This can cause:
// - Order book traversal issues
// - Failed order removal
// - Potential DoS when order book is full
//
// Run PoC:
//   forge test --match-test testPoCH01_PrevOrderIdNotPersisted -vvv
// =============================================================================

import {Test, console} from "forge-std/Test.sol";
import {CLOBTestBase} from "test/clob/utils/CLOBTestBase.sol";
import {Order} from "contracts/clob/types/Order.sol";
import {Side} from "contracts/clob/types/Order.sol";
import {ICLOB} from "contracts/clob/ICLOB.sol";

contract PoCH01PrevOrderIdNotPersistedTest is CLOBTestBase {
    function setUp() public override {
        super.setUp();
    }

    // -------------------------------------------------------------------------
    // PoC: Demonstrate that prevOrderId is not persisted
    // -------------------------------------------------------------------------
    //
    // Expected result on UNPATCHED code : PASS (prevOrderId is 0, proving bug)
    // Expected result after the fix     : FAIL (prevOrderId correctly points to first order)
    function testPoCH01_PrevOrderIdNotPersisted() public {
        console.log("=== H-01: prevOrderId Not Persisted PoC ===");

        // Post first order at price 1 ether
        uint256 price = 1 ether;
        setupOrder(Side.BUY, users[0], 1 ether, price);

        // Post second order at same price - this should link to first order
        setupOrder(Side.BUY, users[0], 0.5 ether, price);

        // Get the order IDs
        uint256 orderId1 = clob.getNextOrderId() - 2; // First order
        uint256 orderId2 = clob.getNextOrderId() - 1; // Second order

        console.log("Order 1 ID:", orderId1);
        console.log("Order 2 ID:", orderId2);

        // Retrieve both orders from storage
        Order memory firstOrder = clob.getOrder(orderId1);
        Order memory secondOrder = clob.getOrder(orderId2);

        console.log("First Order - nextOrderId:", firstOrder.nextOrderId.unwrap());
        console.log("Second Order - prevOrderId:", secondOrder.prevOrderId.unwrap());

        // BUG: secondOrder.prevOrderId should be orderId1, but it will be 0
        // because order.prevOrderId was assigned in memory, not storage
        assertEq(
            secondOrder.prevOrderId.unwrap(),
            0,
            "BUG CONFIRMED: prevOrderId is 0 instead of orderId1 (not persisted)"
        );

        console.log(">>> PoC PASSED: prevOrderId was not persisted to storage");
        console.log("    This breaks the double-linked list structure");
    }
}
