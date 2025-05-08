from web3 import Web3
import solcx
import json
from eth_account import Account
from eth_account.signers.local import LocalAccount


w3 = Web3(Web3.HTTPProvider('http://172.18.64.1:7545'))
print(w3.is_connected())
private_key = "0x48efb65fe35c554626120dd62752469bce17e9c8e9210079f0956d89e6254f59"

account: LocalAccount = Account.from_key(private_key)

authenticator_abi = """
[
	{
		"inputs": [
			{
				"internalType": "contract VerifierC",
				"name": "_verifierC",
				"type": "address"
			},
			{
				"internalType": "contract VerifierD",
				"name": "_verifierD",
				"type": "address"
			}
		],
		"stateMutability": "nonpayable",
		"type": "constructor"
	},
	{
		"inputs": [],
		"name": "N_ATTRIBUTE",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "N_MINER",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "THRESHOLD",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"components": [
					{
						"components": [
							{
								"internalType": "uint256",
								"name": "X",
								"type": "uint256"
							},
							{
								"internalType": "uint256",
								"name": "Y",
								"type": "uint256"
							}
						],
						"internalType": "struct Pairing.G1Point",
						"name": "a",
						"type": "tuple"
					},
					{
						"components": [
							{
								"internalType": "uint256[2]",
								"name": "X",
								"type": "uint256[2]"
							},
							{
								"internalType": "uint256[2]",
								"name": "Y",
								"type": "uint256[2]"
							}
						],
						"internalType": "struct Pairing.G2Point",
						"name": "b",
						"type": "tuple"
					},
					{
						"components": [
							{
								"internalType": "uint256",
								"name": "X",
								"type": "uint256"
							},
							{
								"internalType": "uint256",
								"name": "Y",
								"type": "uint256"
							}
						],
						"internalType": "struct Pairing.G1Point",
						"name": "c",
						"type": "tuple"
					}
				],
				"internalType": "struct Proof",
				"name": "proof",
				"type": "tuple"
			},
			{
				"internalType": "uint256[159]",
				"name": "input",
				"type": "uint256[159]"
			}
		],
		"name": "authenthicate",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "pseudonym",
				"type": "address"
			}
		],
		"name": "malicious",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"components": [
					{
						"components": [
							{
								"internalType": "uint256",
								"name": "X",
								"type": "uint256"
							},
							{
								"internalType": "uint256",
								"name": "Y",
								"type": "uint256"
							}
						],
						"internalType": "struct Pairing.G1Point",
						"name": "a",
						"type": "tuple"
					},
					{
						"components": [
							{
								"internalType": "uint256[2]",
								"name": "X",
								"type": "uint256[2]"
							},
							{
								"internalType": "uint256[2]",
								"name": "Y",
								"type": "uint256[2]"
							}
						],
						"internalType": "struct Pairing.G2Point",
						"name": "b",
						"type": "tuple"
					},
					{
						"components": [
							{
								"internalType": "uint256",
								"name": "X",
								"type": "uint256"
							},
							{
								"internalType": "uint256",
								"name": "Y",
								"type": "uint256"
							}
						],
						"internalType": "struct Pairing.G1Point",
						"name": "c",
						"type": "tuple"
					}
				],
				"internalType": "struct Proof",
				"name": "proof",
				"type": "tuple"
			},
			{
				"internalType": "uint256[9]",
				"name": "input",
				"type": "uint256[9]"
			}
		],
		"name": "openPIA",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "owner",
		"outputs": [
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "pseudonym",
				"type": "address"
			},
			{
				"internalType": "uint256",
				"name": "y_i",
				"type": "uint256"
			}
		],
		"name": "queryMIA",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "pseudonym",
				"type": "address"
			}
		],
		"name": "queryPIA",
		"outputs": [
			{
				"internalType": "uint256[6][3]",
				"name": "result",
				"type": "uint256[6][3]"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "ps",
				"type": "address"
			}
		],
		"name": "queryPS",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
]
"""

case_abi = """
[
	{
		"inputs": [],
		"stateMutability": "nonpayable",
		"type": "constructor"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "g_h_e",
				"type": "uint256"
			}
		],
		"name": "access",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "investigator",
				"type": "address"
			}
		],
		"name": "addInvestigator",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "trial",
				"type": "address"
			}
		],
		"name": "addTrial",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "owner",
		"outputs": [
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "investigator",
				"type": "address"
			}
		],
		"name": "removeInvestigator",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256[7]",
				"name": "r_u",
				"type": "uint256[7]"
			},
			{
				"internalType": "uint256",
				"name": "g_h_e",
				"type": "uint256"
			}
		],
		"name": "upload",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	}
]
"""

trial_abi = """
[
	{
		"inputs": [
			{
				"internalType": "contract VerifierD",
				"name": "_verifierD",
				"type": "address"
			},
			{
				"internalType": "address[]",
				"name": "_voters",
				"type": "address[]"
			},
			{
				"internalType": "address",
				"name": "_judge",
				"type": "address"
			}
		],
		"stateMutability": "nonpayable",
		"type": "constructor"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"name": "candidates",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256[4]",
				"name": "vote",
				"type": "uint256[4]"
			},
			{
				"internalType": "uint256[7]",
				"name": "proof",
				"type": "uint256[7]"
			}
		],
		"name": "castVote",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "judge",
		"outputs": [
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"components": [
					{
						"components": [
							{
								"internalType": "uint256",
								"name": "X",
								"type": "uint256"
							},
							{
								"internalType": "uint256",
								"name": "Y",
								"type": "uint256"
							}
						],
						"internalType": "struct Pairing.G1Point",
						"name": "a",
						"type": "tuple"
					},
					{
						"components": [
							{
								"internalType": "uint256[2]",
								"name": "X",
								"type": "uint256[2]"
							},
							{
								"internalType": "uint256[2]",
								"name": "Y",
								"type": "uint256[2]"
							}
						],
						"internalType": "struct Pairing.G2Point",
						"name": "b",
						"type": "tuple"
					},
					{
						"components": [
							{
								"internalType": "uint256",
								"name": "X",
								"type": "uint256"
							},
							{
								"internalType": "uint256",
								"name": "Y",
								"type": "uint256"
							}
						],
						"internalType": "struct Pairing.G1Point",
						"name": "c",
						"type": "tuple"
					}
				],
				"internalType": "struct Proof",
				"name": "proof",
				"type": "tuple"
			},
			{
				"internalType": "uint256[9]",
				"name": "input",
				"type": "uint256[9]"
			},
			{
				"internalType": "uint256[2]",
				"name": "r",
				"type": "uint256[2]"
			},
			{
				"internalType": "uint256",
				"name": "d",
				"type": "uint256"
			}
		],
		"name": "openVote",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "owner",
		"outputs": [
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "privateKey",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"name": "publicKey",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256[2]",
				"name": "pkey",
				"type": "uint256[2]"
			},
			{
				"internalType": "uint256[2][2]",
				"name": "_candidates",
				"type": "uint256[2][2]"
			}
		],
		"name": "publishParameter",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"name": "voters",
		"outputs": [
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
]
"""

authenticator = w3.eth.contract(address = "0x9fe6f21a30e98F80534a0b913dB6ad9c1Ec9dd88", abi = authenticator_abi)
case = w3.eth.contract(address = "0x3CaC98bD75E6B7847751D0db4E0B9E6538104a23", abi = case_abi)
trial = w3.eth.contract(address = "0x35FbE154baeCBD3280C3083b4187cc34E4d1A311", abi = trial_abi)

data = json.load(open("Circuit_C/proof.json"))
"""
tx_hash = authenticator.functions.authenthicate(data["proof"], data["inputs"]).transact({
    "from": account
})
"""

ad = "0xC2f56E89492f07E895bFF46682Ffd1c53F474E4D"
from PPChain import *

def test_evidence():
    k = 6
    n = 10

    ip = IP()
    validators = [Validator() for _ in range(n)]
    user = User(k, n, ip, validators,
    [
        FQ(getRandomRange(0, 2 ** 128)),
        FQ(1)
    ])

    cert_i = user.register()
    user.authenticate()


    E = os.urandom(3000000)
        
    R_u = (user.provide(E))
    g_h_e = bytes_to_long(keccak.new(digest_bits=256).update(E).digest())

    tx_hash = case.functions.upload([
        R_u[0][0].x.n, R_u[0][0].y.n, R_u[0][1].x.n, R_u[0][1].y.n, R_u[1][0].x.n, R_u[1][0].y.n, R_u[1][1].n
    ], g_h_e).transact({'from': ad})
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print(tx_receipt)

def test_trial():
    proof = (
        (0x01, 0x02),
        ([0x03, 0x04], [0x05, 0x06]),
        (0x07, 0x08)
    )
    inputs = [
        0x25c8535b93302f63a870de2e3567c3b968fbea29110e991e845d77c0235fb93f,
        0x2faacba4fd8ffe287fbdf2692eee401d1037c19e9c1786d0d6960fd8b33b34cc,
        0x1def47877f13d519b062aee4ca3e6df80167d7e7a0f917dd467181b11a991203,
        0x26f080d2f3b91bcc850333d6f25f43f70a32c6041b75090c1aa9cb6cff3b5d01,
        0x22ad371bf8df267b18a51fc08ea9a8c4cd0b62a6ee32a33d88893cf8ab062abc,
        0x1cae35a7c79474c590800dd9abe1bb58d35cea2a8b3b100ba20a252db2710053,
        0x0c6895f1ac429655ef971a029c2cad0225b741ddc0f6a37b3bf7f8954b333172,
        0x0a48419a3d9c0f55081263f039cdea7765f1e82fde1c987607a8e106285cfe20,
        0x0000000000000000000000000000000000000000000000000000000000000001
    ]
    print(trial.functions.openVote)
    tx_hash = trial.functions.openVote(
        proof, inputs, [1, 2], 1
    )
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print(receipt)

    
test_trial()

