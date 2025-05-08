// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.0;

import {Proof} from "./Pairing.sol";
import {VerifierC} from "./VerifierC.sol";
import {VerifierD} from "./VerifierD.sol";

contract Authenticator {
    uint256 public constant N_MINER = 10;
    uint256 public constant N_ATTRIBUTE = 2;
    uint256 public constant THRESHOLD = 6;

    struct AuthenticateData {
        address pseudonym;
        uint256 h_hat_i;
        uint256[2][2][N_MINER] C_n;
    }

    struct Commitment {
        address pseudonym;
        uint256[N_ATTRIBUTE] Y_t;
    }

    struct Shares {
        address pseudonym;
        uint8 share_count;
        uint256[3][THRESHOLD] shares;
    }

    AuthenticateData[] private authenticateTable;
    Commitment[] private commitmentTable;
    Shares[] private sharesTable;

    VerifierC private immutable verifierC;
    VerifierD private immutable verifierD;
    address public immutable owner;

    constructor(VerifierC _verifierC, VerifierD _verifierD) {
        verifierC = _verifierC;
        verifierD = _verifierD;
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    function authenticate(Proof calldata proof, uint256[159] calldata input) external {
        require(input[158] == 1, "Invalid final input value");
        require(verifierC.verifyTx(proof, input), "Proof verification failed");

        uint256 h_hat_i = extractHHat(input);
        checkDuplicateHHat(h_hat_i);

        AuthenticateData memory auth = parseAuthenticateData(input, h_hat_i);
        Commitment memory com = parseCommitmentData(input);

        authenticateTable.push(auth);
        commitmentTable.push(com);
    }

    function extractHHat(uint256[159] calldata input) internal pure returns (uint256 h_hat_i) {
        for (uint256 i = 0; i < 32; ++i) {
            h_hat_i |= (input[i] << (8 * i));
        }
    }

    function checkDuplicateHHat(uint256 h_hat_i) internal view {
        for (uint256 i = 0; i < authenticateTable.length; ++i) {
            require(authenticateTable[i].h_hat_i != h_hat_i, "Duplicate h_hat_i");
        }
    }

    function parseAuthenticateData(uint256[159] calldata input, uint256 h_hat_i) internal view returns (AuthenticateData memory auth) {
        auth.pseudonym = msg.sender;
        auth.h_hat_i = h_hat_i;

        uint256 offset = 34;
        for (uint32 i = 0; i < N_MINER; ++i) {
            for (uint32 j = 0; j < 2; ++j) {
                for (uint32 k = 0; k < 2; ++k) {
                    auth.C_n[i][j][k] = input[offset++];
                }
            }
        }
    }

    function parseCommitmentData(uint256[159] calldata input) internal view returns (Commitment memory com) {
        com.pseudonym = msg.sender;
        uint256 offset = 34 + N_MINER * 4;

        for (uint32 i = 0; i < N_ATTRIBUTE; ++i) {
            uint256 y_i;
            for (uint32 j = 0; j < 32; ++j) {
                y_i |= (input[offset++] << (8 * j));
            }
            com.Y_t[i] = y_i;
        }
    }


    function queryPS(address ps) external view returns (bool) {
        for (uint256 i = 0; i < authenticateTable.length; ++i) {
            if (authenticateTable[i].pseudonym == ps) {
                return true;
            }
        }
        return false;
    }

    function malicious(address pseudonym) external onlyOwner {
        uint256[3][THRESHOLD] memory emptyShares;
        Shares memory share = Shares({
            pseudonym: pseudonym,
            share_count: 0,
            shares: emptyShares
        });
        sharesTable.push(share);
    }

    function openPIA(Proof calldata proof, uint256[9] calldata input) external {
        require(input[8] == 1, "Invalid final input value");
        require(verifierD.verifyTx(proof, input), "Proof verification failed");

        for (uint256 i = 0; i < authenticateTable.length; ++i) {
            for (uint32 j = 0; j < N_MINER; ++j) {
                if (
                    authenticateTable[i].C_n[j][0][0] == input[0] &&
                    authenticateTable[i].C_n[j][0][1] == input[1] &&
                    authenticateTable[i].C_n[j][1][0] == input[2] &&
                    authenticateTable[i].C_n[j][1][1] == input[3]
                ) {
                    address ps = authenticateTable[i].pseudonym;
                    for (uint256 k = 0; k < sharesTable.length; ++k) {
                        if (sharesTable[k].pseudonym == ps && sharesTable[k].share_count < THRESHOLD) {
                            uint8 c = sharesTable[k].share_count;
                            sharesTable[k].shares[c][0] = j + 1;
                            sharesTable[k].shares[c][1] = input[4];
                            sharesTable[k].shares[c][2] = input[5];
                            sharesTable[k].share_count++;
                            break;
                        }
                    }
                }
            }
        }
    }

    function queryPIA(address pseudonym) external view onlyOwner returns (uint256[3][THRESHOLD] memory result) {
        for (uint256 i = 0; i < sharesTable.length; ++i) {
            if (sharesTable[i].pseudonym == pseudonym) {
                return sharesTable[i].shares;
            }
        }
        revert("Pseudonym has not been considered malicious yet!");
    }

    function queryMIA(address pseudonym, uint256 y_i) external view returns (bool) {
        for (uint256 i = 0; i < commitmentTable.length; ++i) {
            if (commitmentTable[i].pseudonym == pseudonym) {
                for (uint32 j = 0; j < N_ATTRIBUTE; ++j) {
                    if (commitmentTable[i].Y_t[j] == y_i) {
                        return true;
                    }
                }
                return false;
            }
        }
        return false;
    }
}
