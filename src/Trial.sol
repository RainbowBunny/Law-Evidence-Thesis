// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.0;

import {Proof} from "./Pairing.sol";
import {VerifierD} from "./VerifierD.sol";

contract Trial {
  address public owner;
  address public judge;
  address[] public voters;
  bool[] voted;
  uint256[2] public publicKey;
  uint256[2][2] public candidates;
  uint256 public privateKey;
  uint256 finalDecision;
  VerifierD private verifierD;

  enum State {
    Init,
    Voting,
    Settled
  }

  State currentState;

  constructor(VerifierD _verifierD, address[] memory _voters, address _judge) {
    verifierD = _verifierD;
    owner = tx.origin;
    currentState = State.Init;
    voters = _voters;
    judge = _judge;
    voted = new bool[](voters.length);
  }

  modifier onlyOwner {
    require(msg.sender == owner);
    _;
  }

  function publishParameter(uint256[2] memory pkey, uint256[2][2] memory _candidates) public {
    require(msg.sender == judge);
    require(currentState == State.Init, "Need to be in init state!");
    publicKey = pkey;
    candidates = _candidates;
    currentState = State.Voting;
  }

  function castVote(uint256[4] memory vote, uint256[12] memory proof) public {
    require(currentState == State.Voting);
    uint id = voters.length;
    for (uint32 i = 0; i < voters.length; i++) {
      if (voters[i] == msg.sender && voted[i] == false) {
        id = i;
      }
    }
    require(id != voters.length, "Voter does not exist or has voted!");
    // Check onchain
    voted[id] = true;
  }

  function openVote(Proof memory proof, uint[9] memory input, uint256[2] memory r, uint256 d) public {
    require(msg.sender == judge);
    require(input[8] == 1);
    require(verifierD.verifyTx(proof, input), "Proof verification failed");
    currentState = State.Settled;
    finalDecision = d;
  }
}