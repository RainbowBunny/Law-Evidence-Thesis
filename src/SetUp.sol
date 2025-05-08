// SPDX-License-Identifier: LGPL-3.0-only
// This file is LGPL3 Licensed
pragma solidity ^0.8.0;

/**
 * @title Elliptic curve operations on twist points for alt_bn128
 * @author Mustafa Al-Bassam (mus@musalbas.com)
 * @dev Homepage: https://github.com/musalbas/solidity-BN256G2
 */

import "./VerifierC.sol";
import "./VerifierD.sol";

contract SetUp {
  VerifierC public verifierC;
  VerifierD public verifierD;

  constructor() {
    verifierC = new VerifierC();
    verifierD = new VerifierD();
  }
}