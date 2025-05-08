// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.0;

contract Case {
  struct EvidenceUpload {
    address uploader;
    uint256[7] r_u;
    uint256 g_h_e;
    uint256 timestamp;
  }

  struct EvidenceAccess {
    address accessor;
    uint256 g_h_e;
    uint256 timestamp;
  }

  address public owner;
  address[] private investigators;
  EvidenceUpload[] uploadRecords;
  EvidenceAccess[] accessRecords;
  address[] trials;

  constructor() {
    owner = tx.origin;
  }

  modifier onlyOwner {
    require(msg.sender == owner);
    _;
  }

  modifier isInvestigator {
    bool ok = false;
    for (uint i = 0; i < investigators.length; i++) {
      if (investigators[i] == msg.sender) {
        ok = true;
      }
    }
    require(ok);
    _;
  }

  function addInvestigator(address investigator) public onlyOwner {
    investigators.push(investigator);
  }

  function removeInvestigator(address investigator) public onlyOwner {
    for (uint i = 0; i < investigators.length; i++) {
      if (investigators[i] == investigator) {
        investigators[i] = investigators[investigators.length - 1];
        investigators.pop();
        break;
      }
    }
  }

  function upload(uint256[7] memory r_u, uint256 g_h_e) 
    public isInvestigator() {
    EvidenceUpload memory evidenceUpload;
    evidenceUpload.uploader = msg.sender;
    evidenceUpload.r_u = r_u;
    evidenceUpload.g_h_e = g_h_e;
    evidenceUpload.timestamp = block.timestamp;

    uploadRecords.push(evidenceUpload);
  }

  function access(uint256 g_h_e) public isInvestigator() {
    bool exist = false;
    for (uint256 i = 0; i < uploadRecords.length; i++) {
      if (uploadRecords[i].g_h_e == g_h_e) {
        exist = true;
      }
    }

    require(exist);

    EvidenceAccess memory evidenceAccess;
    evidenceAccess.accessor = msg.sender;
    evidenceAccess.g_h_e = g_h_e;
    evidenceAccess.timestamp = block.timestamp;

    accessRecords.push(evidenceAccess);
  }

  function addTrial(address trial) public onlyOwner {
    trials.push(trial);
  }
}