// SPDX-License-Identifier: LGPL-3.0-only
// This file is LGPL3 Licensed
pragma solidity ^0.8.0;

/**
 * @title Elliptic curve operations on twist points for alt_bn128
 * @author Mustafa Al-Bassam (mus@musalbas.com)
 * @dev Homepage: https://github.com/musalbas/solidity-BN256G2
 */

import "./Pairing.sol";

contract VerifierD {
    using Pairing for *;

    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.h= Pairing.G2Point([uint256(0x0a465dae2fd19928368aa36b06d8b540305ed9baa60ffcf4e7d8acc4912e272f), uint256(0x2a8db8aebae3f3838e53b461e7b3852fa3835ac704ca80a060b53715937bcb36)], [uint256(0x0508d5ca82484fce59819d4d1cbf2215619bc5644f371aecb88469193f591f65), uint256(0x26ca88e3defac30caa97ca97a5d856a25ce3a67e51831933ca327b0648e894cb)]);
        vk.g_alpha = Pairing.G1Point(uint256(0x1ccfea83adebf8168a46d42c66345a39306d38d22e3fccb49357497ef7c6ebc8), uint256(0x156adc89be36ac9617a9254023fe6ba443f19a1a075b603fda2d69ca4eca8074));
        vk.h_beta = Pairing.G2Point([uint256(0x2f79f046293bc7dff2694f534b5bc9a5eba4ab2ab9b9882a6e21904b30c0fab2), uint256(0x1500d411e9c9fb348e5bbd80c0cd9ef0b0600d78300d241af2dcf6847d8ca9e3)], [uint256(0x19498be4a89714e356e809b9213763d415fac0af43b793a48b9d081241c0a76f), uint256(0x06d9959ea1fa1aa375d127da28e14af491e63036e033ab719f22657a59dc0f83)]);
        vk.g_gamma = Pairing.G1Point(uint256(0x0cc720a93ab8a3a065f6ca83ddd936df3a8226c540ca85c3f5c300ca1131aa04), uint256(0x08aebf98f6d7646850ed8b16060538433f1afc905c859ffd71d44186293f20b9));
        vk.h_gamma = Pairing.G2Point([uint256(0x0a465dae2fd19928368aa36b06d8b540305ed9baa60ffcf4e7d8acc4912e272f), uint256(0x2a8db8aebae3f3838e53b461e7b3852fa3835ac704ca80a060b53715937bcb36)], [uint256(0x0508d5ca82484fce59819d4d1cbf2215619bc5644f371aecb88469193f591f65), uint256(0x26ca88e3defac30caa97ca97a5d856a25ce3a67e51831933ca327b0648e894cb)]);
        vk.query = new Pairing.G1Point[](10);
        vk.query[0] = Pairing.G1Point(uint256(0x0d0c75bf6ff28a246556b6fdc4bf7f8bbbab796f817cb5f5006a53cad875b53b), uint256(0x0e2b6250f69f867fad27df5dc005a102f23e7e8cdb1dc7d7a5731b426b0e0ab6));
        vk.query[1] = Pairing.G1Point(uint256(0x231ca2fa88cc90579ac264cde72972316eeeac8d4a4f90d45610dd7b64a373d6), uint256(0x2fcf25796c7f2bf6184445e118ef9cfde1d0cb3396ea9f53021107f87a76a533));
        vk.query[2] = Pairing.G1Point(uint256(0x1cea43c77ba49cefb55218e69efea1a692539663b229cd044783989d142bfcae), uint256(0x07a1f92f7180cc826e7d676ebbbab941a8d0f2dc18cbea76f137789f491b9763));
        vk.query[3] = Pairing.G1Point(uint256(0x2e47ef1fe422be500c9cd70f48f061a97335d5305754aea2de7c2277d485be67), uint256(0x15a275f290972d51704468aeb58e3652afefcafa63c7fd5832240f3e9e1f9325));
        vk.query[4] = Pairing.G1Point(uint256(0x18635fe5cef564b9a34ed557620332b61684d91e79e5e475a88cab2e3986eb1a), uint256(0x00a809bdccb4f031a9fb37adea71d7f7ddd0d7592da163622c3e69cdc0a5cd94));
        vk.query[5] = Pairing.G1Point(uint256(0x2319e30e0f8b746e4a843b17264b05875c917c2197d2682da3f74802541bbad4), uint256(0x209480739c2c85c687c019f68a85a70938b519ef31556367a17bfc7894f239af));
        vk.query[6] = Pairing.G1Point(uint256(0x1a00f1d5c6a3f1136b385adb892fae8429647614c1a9a87ec0393f8d23dcc1d2), uint256(0x1b89c51305d3cf0b7c4b9e8c12879fcdc2facc8d552c02961893a7763d87a972));
        vk.query[7] = Pairing.G1Point(uint256(0x12fee5ebd11f2b68006fab35ce16bce2caeefd95136383848b95e93d6172cb7a), uint256(0x09ed4cc52f2b453301e79df79d271ea760104e0fda2732b950b1100dfb7fdf51));
        vk.query[8] = Pairing.G1Point(uint256(0x28d59d80b8d0ff419b759b25345a3c18ba1785b50bf6ec9ef089a27437d1f7ff), uint256(0x19fc7f16cd1892a51519a3198a895a80a7fe096ebdb768c6e99e646bdc0db4f4));
        vk.query[9] = Pairing.G1Point(uint256(0x0e3197dfcbee0597829058628b1ef2ca8992a800b276b674e3dc39d4f70ec780), uint256(0x0b0a94eaa25ce6f432e8f8c52a1dc63bbfffc7e79087260ae510f16b090083a0));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.query.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.query[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.query[0]);
        /**
         * e(A*G^{alpha}, B*H^{beta}) = e(G^{alpha}, H^{beta}) * e(G^{psi}, H^{gamma})
         *                              * e(C, H)
         * where psi = \sum_{i=0}^l input_i pvk.query[i]
         */
        if (!Pairing.pairingProd4(vk.g_alpha, vk.h_beta, vk_x, vk.h_gamma, proof.c, vk.h, Pairing.negate(Pairing.addition(proof.a, vk.g_alpha)), Pairing.addition(proof.b, vk.h_beta))) return 1;
        /**
         * e(A, H^{gamma}) = e(G^{gamma}, B)
         */
        if (!Pairing.pairingProd2(proof.a, vk.h_gamma, Pairing.negate(vk.g_gamma), proof.b)) return 2;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[9] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](9);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
