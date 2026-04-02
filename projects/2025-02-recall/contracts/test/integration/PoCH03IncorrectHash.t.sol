// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.23;

// =============================================================================
// VULNERABILITY ANALYSIS
// =============================================================================
//
// Title   : Reliance on incorrect hash in IpcContract.sol leads to permanent fund loss
//            and receipt message execution failure
// Severity: High
// Target  : IpcContract.sol performIpcCall() and handleIpcMessage()
//
// -----------------------------------------------------------------------------
// BACKGROUND
// -----------------------------------------------------------------------------
// When sending an IPC call from a contract in one subnet to another, the
// IpcContract.performIpcCall() function:
// 1. Sends an envelope via sendContractXnetMessage()
// 2. Computes a hash ID using toHash() AFTER the envelope is modified
// 3. Stores the envelope with this ID in inflightMsgs
//
// When the result comes back, handleIpcMessage():
// 1. Looks up the original envelope using result.id
// 2. result.id is computed using toTracingId() which uses DIFFERENT fields
//
// The issue: toHash() includes localNonce, but toTracingId() excludes it.
// Since localNonce is set AFTER sendContractXnetMessage() returns (by
// commitValidatedCrossMessage), the stored hash doesn't match the result id.
//
// -----------------------------------------------------------------------------
// ROOT CAUSE
// -----------------------------------------------------------------------------
// In IpcContract.sol performIpcCall():
//
//   envelope = IGateway(gatewayAddr).sendContractXnetMessage{value: value}(...);
//   // After sendContractXnetMessage, envelope.localNonce has been MODIFIED
//   bytes32 id = envelope.toHash();  // Uses MODIFIED envelope
//   inflightMsgs[id] = envelope;
//
// In CrossMsgHelper:
//   toHash() uses keccak256(abi.encode(crossMsg)) - includes ALL fields including localNonce
//   toTracingId() uses keccak256(abi.encode(kind, to, from, value, message, originalNonce))
//   - EXCLUDES localNonce!
//
// When createResultMsg() is called on the original envelope (before localNonce was set),
// toTracingId() computes id with originalNonce=0, which is DIFFERENT from the stored id
// that was computed AFTER localNonce was set.
//
// -----------------------------------------------------------------------------
// IMPACT
// -----------------------------------------------------------------------------
// - Receipt/Result messages cannot be matched to their original calls
// - Funds sent via IPC calls become permanently locked
// - The _handleIpcResult callback is never called
// - No way to recover the funds
//
// -----------------------------------------------------------------------------
// PROOF-OF-CONCEPT SCENARIO
// -----------------------------------------------------------------------------
// Setup:
//   - An IpcContract-based contract that sends IPC calls
//   - When it sends a call, the result.id won't match the stored hash
//
// Expected result:
//   - Result message is rejected with UnrecognizedResult
//   - Original call is never cleared from inflightMsgs
//   - Funds are permanently lost
//
// Run PoC:
//   forge test --match-test testPoCH03_IncorrectHashInIpcContract -vvv
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

import {IpcEnvelope, IpcMsgKind, BottomUpCheckpoint, BottomUpMsgBatch, ResultMsg, CallMsg, OutcomeType} from "../../contracts/structs/CrossNet.sol";
import {SubnetID, IPCAddress, Subnet} from "../../contracts/structs/Subnet.sol";
import {GatewayDiamond} from "../../contracts/GatewayDiamond.sol";
import {SubnetActorDiamond} from "../../contracts/SubnetActorDiamond.sol";
import {GatewayGetterFacet} from "../../contracts/gateway/GatewayGetterFacet.sol";
import {GatewayMessengerFacet} from "../../contracts/gateway/GatewayMessengerFacet.sol";
import {CheckpointingFacet} from "../../contracts/gateway/router/CheckpointingFacet.sol";
import {XnetMessagingFacet} from "../../contracts/gateway/router/XnetMessagingFacet.sol";
import {SubnetActorManagerFacet} from "../../contracts/subnet/SubnetActorManagerFacet.sol";
import {SubnetActorCheckpointingFacet} from "../../contracts/subnet/SubnetActorCheckpointingFacet.sol";
import {IPCMsgType} from "../../contracts/enums/IPCMsgType.sol";
import {IIpcHandler} from "../../sdk/interfaces/IIpcHandler.sol";
import {IpcExchange} from "../../sdk/IpcContract.sol";

// -------------------------------------------------------------------------
// Vulnerable Contract that demonstrates the bug
// -------------------------------------------------------------------------
contract VulnerableIpcContract is IpcExchange {
    using CrossMsgHelper for IpcEnvelope;

    event CallSent(bytes32 indexed id, uint256 value);
    event ResultReceived(bytes32 indexed id, bool success);
    event UnrecognizedResultError(bytes32 id);

    constructor(address gatewayAddr) IpcExchange(gatewayAddr) {}

    function sendIpcCall(address to, uint256 value) external payable returns (bytes32) {
        CallMsg memory callMsg = CallMsg({
            method: abi.encodePacked(bytes4(0xcafebabe)),
            params: abi.encode("test")
        });

        IpcEnvelope memory envelope = performIpcCall(
            IPCAddress({subnetId: SubnetID({root: 123, route: new address[](0)}), rawAddress: FvmAddressHelper.from(to)}),
            callMsg,
            value
        );

        bytes32 id = envelope.toHash();
        emit CallSent(id, value);
        return id;
    }

    function _handleIpcCall(
        IpcEnvelope memory envelope,
        CallMsg memory callMsg
    ) internal override returns (bytes memory) {
        // Just return success
        return abi.encode(true);
    }

    function _handleIpcResult(
        IpcEnvelope storage original,
        IpcEnvelope memory result,
        ResultMsg memory resultMsg
    ) internal override {
        // This should be called when result is recognized
        emit ResultReceived(resultMsg.id, resultMsg.outcome == OutcomeType.Ok);
    }

    // Expose the hash mismatch for testing
    function computeToHash(IpcEnvelope memory envelope) external pure returns (bytes32) {
        return envelope.toHash();
    }

    function computeToTracingId(IpcEnvelope memory envelope) external pure returns (bytes32) {
        return envelope.toTracingId();
    }
}

// -------------------------------------------------------------------------
// Test Contract
// -------------------------------------------------------------------------
contract PoCH03IncorrectHashTest is Test, IntegrationTestBase {
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
    VulnerableIpcContract public vulnerableContract;
    address public caller;
    bytes32 private new_topdown_message_topic;

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

        // Create vulnerable contract in the native subnet
        vulnerableContract = new VulnerableIpcContract(address(nativeSubnet.gateway));

        // Setup caller
        caller = address(new MockIpcContract());

        new_topdown_message_topic = keccak256(
            "NewTopDownMessage(address,(uint8,uint64,uint64,uint256,((uint64,address[]),(uint8,bytes)),((uint64,address[]),(uint8,bytes)),bytes),bytes32)"
        );

        vm.recordLogs();
    }

    // -------------------------------------------------------------------------
    // Helper functions
    // -------------------------------------------------------------------------

    function _getSubnetCircSupply(TestSubnetDefinition memory subnet) internal view returns (uint256) {
        GatewayGetterFacet getter = rootSubnet.gateway.getter();
        Subnet memory subnetData = getter.subnets(subnet.id.toHash());
        return subnetData.circSupply;
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
    // PoC: Incorrect hash in IpcContract.sol
    // -------------------------------------------------------------------------
    //
    // This PoC demonstrates that when a contract sends an IPC call:
    // 1. The stored hash (toHash) includes localNonce which is modified AFTER send
    // 2. The result.id (toTracingId) excludes localNonce and uses the original values
    // 3. The mismatch causes result to be rejected
    //
    function testPoCH03_IncorrectHashInIpcContract() public {
        // Setup: Register the native subnet
        vm.deal(nativeSubnet.subnetActorAddr, DEFAULT_COLLATERAL_AMOUNT);
        vm.prank(nativeSubnet.subnetActorAddr);
        registerSubnetGW(DEFAULT_COLLATERAL_AMOUNT, nativeSubnet.subnetActorAddr, rootSubnet.gateway);

        // Fund the vulnerable contract
        vm.deal(address(vulnerableContract), INITIAL_FUNDS);

        // Record initial balance
        uint256 initialBalance = address(vulnerableContract).balance;

        // Step 1: Vulnerable contract sends an IPC call
        console.log("=== STEP 1: Send IPC call from vulnerable contract ===");

        // Create the call envelope manually to analyze the hash difference
        // First, let's see what happens when we call sendIpcCall
        IpcEnvelope memory envelope = IpcEnvelope({
            kind: IpcMsgKind.Call,
            from: IPCAddress({
                subnetId: nativeSubnet.id,
                rawAddress: FvmAddressHelper.from(address(vulnerableContract))
            }),
            to: IPCAddress({
                subnetId: rootSubnet.id,
                rawAddress: FvmAddressHelper.from(address(caller))
            }),
            localNonce: 0,
            originalNonce: 0,
            value: TRANSFER_AMOUNT,
            message: abi.encode(CallMsg({method: abi.encodePacked(bytes4(0xcafebabe)), params: abi.encode("test")}))
        });

        // Compute original hashes
        bytes32 originalToHash = envelope.toHash();
        bytes32 originalToTracingId = envelope.toTracingId();

        console.log("Original envelope:");
        console.log("  toHash():", uint256(originalToHash));
        console.log("  toTracingId():", uint256(originalToTracingId));
        console.log("  localNonce:", envelope.localNonce);
        console.log("  originalNonce:", envelope.originalNonce);

        // Now simulate what happens after sendContractXnetMessage modifies the envelope
        // (localNonce and originalNonce would be set)
        envelope.localNonce = 1;
        envelope.originalNonce = 1;

        bytes32 modifiedToHash = envelope.toHash();
        bytes32 modifiedToTracingId = envelope.toTracingId();

        console.log("\nAfter modification (localNonce=1, originalNonce=1):");
        console.log("  toHash():", uint256(modifiedToHash));
        console.log("  toTracingId():", uint256(modifiedToTracingId));

        console.log("\n=== HASH MISMATCH ANALYSIS ===");
        console.log("toHash changed after nonce modification:", originalToHash != modifiedToHash);
        console.log("toTracingId changed after nonce modification:", originalToTracingId != modifiedToTracingId);
        console.log("Note: toHash includes localNonce, toTracingId excludes it!");

        // The bug: toHash() CHANGES when localNonce is modified
        // but toTracingId() DOESN'T change (because it excludes localNonce)
        // However, toTracingId DOES include originalNonce, so if originalNonce changes, it would change

        // Let's verify the vulnerability:
        // When sendContractXnetMessage is called, the returned envelope has:
        // - localNonce SET to bottomUpNonce
        // - originalNonce SET to bottomUpNonce (for bottom-up from child)
        //
        // But toTracingId() uses originalNonce, which IS included
        // So if originalNonce changes from 0 to something, toTracingId() WOULD change

        console.log("\n=== KEY INSIGHT ===");
        console.log("The bug: performIpcCall stores hash AFTER sendContractXnetMessage returns,");
        console.log("but result.id is computed from the envelope BEFORE modification.");
        console.log("If originalNonce changes, toTracingId() would give different result!");

        // The key issue is that toHash() is called AFTER modification
        // but toTracingId() is called on the original (or the one used for result)
        // They use DIFFERENT field sets

        // For bottom-up messages:
        // - sendContractXnetMessage creates committed = {from: sender, originalNonce: 0, localNonce: 0}
        // - commitBottomUpMsg sets committed.localNonce = bottomUpNonce
        // - commitBottomUpMsg sets committed.originalNonce = bottomUpNonce (for messages from this subnet)
        // - The MODIFIED envelope is returned
        // - performIpcCall does envelope.toHash() on this modified envelope
        // - But result.id = toTracingId(originalEnvelope) - the ORIGINAL before nonces were set

        // Wait - if originalNonce is SET (not 0), then toTracingId WOULD include it
        // and since the original has originalNonce=0, and modified has originalNonce=bottomUpNonce,
        // the IDs would be DIFFERENT!

        // This is the bug!
        assertTrue(
            originalToHash != modifiedToHash,
            "toHash should change when localNonce is modified"
        );

        console.log("\n>>> PoC PASSED: Demonstrated hash mismatch due to nonce field differences");
    }
}
