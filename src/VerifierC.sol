
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract VerifierC {
    using Pairing for *;
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.h= Pairing.G2Point([uint256(0x0e68ebb6b9dbbe5e6f72c9d066b4005d56abb0097544af7b7295f4730e9a0c74), uint256(0x2e89c5e04ee2ee46fe03088c17d4ee4fab2f5e8d6b4c145b289b55216cf8e4a1)], [uint256(0x19adbbc9c66b5b0d00a14a3ad3876ccf096e937ecec0b5d3bf8f18a52c832507), uint256(0x0e3f256e12b08b3f9292742920711fc24e35dfca2a4e5008e08c9f2fc8f34e22)]);
        vk.g_alpha = Pairing.G1Point(uint256(0x03bb5094a001e895faf59f39d2d363daeee0286abc7f7b78d1e69c000f2d94a6), uint256(0x0804b21add78b98510f0ee87b99cddfe774425aac13e8153ea0cb137825601bd));
        vk.h_beta = Pairing.G2Point([uint256(0x21e6447a11f4ccf7088a958ca1f377bd690164f9a2a51734fae208032f88c226), uint256(0x0c28c989a118db552d678e5430d90a402a9d3d7090acfa0408050d2e74f25c83)], [uint256(0x2316aff6c821ea8c792b4e4ad0e3de804174996fb9006a190f0221352371b622), uint256(0x1efb2866843823fd4ee89760526750fc9705307eb8b0974c7533263c3c3ccf51)]);
        vk.g_gamma = Pairing.G1Point(uint256(0x23951f268792e07b4b6627b14e9343aef8683647c87553ebd533144fb8410dc5), uint256(0x2121bfe9ad64a639a6416b9eb5cae66392adff2536e74dfc9a2404115eef01f0));
        vk.h_gamma = Pairing.G2Point([uint256(0x0e68ebb6b9dbbe5e6f72c9d066b4005d56abb0097544af7b7295f4730e9a0c74), uint256(0x2e89c5e04ee2ee46fe03088c17d4ee4fab2f5e8d6b4c145b289b55216cf8e4a1)], [uint256(0x19adbbc9c66b5b0d00a14a3ad3876ccf096e937ecec0b5d3bf8f18a52c832507), uint256(0x0e3f256e12b08b3f9292742920711fc24e35dfca2a4e5008e08c9f2fc8f34e22)]);
        vk.query = new Pairing.G1Point[](160);
        vk.query[0] = Pairing.G1Point(uint256(0x00ea0cbd9113cf4aa6b3e7ac0109487a37451f75c20e66103c3a22f42d42e9da), uint256(0x0f1ba6ade3b1bb210ad71f7f498099a87fff15a28370466ff4080bbfd3b8f287));
        vk.query[1] = Pairing.G1Point(uint256(0x1da6a4bf08e310ce64d2902c6e8c9dbf4b34d867ff3fe8fe6de1efd0262f0000), uint256(0x216eb8ce074d25ca1a5fc269dd94448ed6516a708259992c0ed5103ce99b8523));
        vk.query[2] = Pairing.G1Point(uint256(0x04714579370d1dfb1adbc15607b3f65a2e5079f78976a1b6779f17cf17ab5651), uint256(0x253bec564fad24637e46434c861fe1a14be3cf0031fdf8d3b91053ea91f2133e));
        vk.query[3] = Pairing.G1Point(uint256(0x04024aefb23c1b761e93bc3d2e96b444c2cd7200aa76eae089224520618fca4d), uint256(0x02acaf45ff35c516b75d7409dd87a1250449bce45150a6e19e588af4f4dc3f1b));
        vk.query[4] = Pairing.G1Point(uint256(0x1effb4e6a29907e4b83ae46d442771fa813a6abc498adbd8caf7d0f8f9397591), uint256(0x15197a9c8c8dd94c66004b281ea5640a83afbb99dd27a2150a3237590a8d6b2d));
        vk.query[5] = Pairing.G1Point(uint256(0x0d3885e184556df91590464b64f3a808f288ec13bef1e3d7ebd224f93a935f33), uint256(0x2bf9c09ca7f65ccbaba4dc9fe84c4cecf7e4b4454326d8748ba5659ae4bbc77b));
        vk.query[6] = Pairing.G1Point(uint256(0x05ad7c7cfd1f57aee21e5bd84915dcec50dd6172ed7ddc0400a66bae53e8b608), uint256(0x03813249663a7d60189648f7b4a6e0fce6232683758ea9c84b9ecbc3bc170781));
        vk.query[7] = Pairing.G1Point(uint256(0x04a5d8b868980fe0d17a1f3eada70fac76af91c6301314358000aef2ffc234b3), uint256(0x01e29946cc00e1403db8a2905d94052a517531f701763e7ffd3732a96bc714d5));
        vk.query[8] = Pairing.G1Point(uint256(0x0a4603927879a57dfd8b207d178ae2659484d6269e582bcf0a01240a4fc469a0), uint256(0x0ed3b404d28bad81a56727d3b65a3c7ad60247facf725032a816ac116a9f5104));
        vk.query[9] = Pairing.G1Point(uint256(0x075221e3212c087dc7199593935920c92a10e0bda30ff3cb3246ac19152e8469), uint256(0x17e2ea542193a3a36771337cbd96c4521af29b5583a8f8d2ca93d805f3b9c6bf));
        vk.query[10] = Pairing.G1Point(uint256(0x285000191edc272289d2e9c55fe004ec41d0678a25ccb6160eeb151bcd6b54b5), uint256(0x0b38835873893e681b9e79cf3588c13df0962d33f4f227c30f6da660b5e64439));
        vk.query[11] = Pairing.G1Point(uint256(0x1fe256a936d66f54621ef9005ec1947fc8595774fa0f9547845fbef8eb2226ba), uint256(0x012d1441f495fae2ba339c2526669a90ba98aa4820207fbb404bf8dd89fbc855));
        vk.query[12] = Pairing.G1Point(uint256(0x2ed4f4f9aedc9358e7ef2a00dd69e6da31e00a26e3cf2e97f6f0ecdb8a3d5540), uint256(0x1ec5502f40543d64c5b68ea78ad4e32393586dac405a72f0e97c0af9e59af5c8));
        vk.query[13] = Pairing.G1Point(uint256(0x1ac0264c643d1d2346c4ee708231d6930f601c49698b77d506f8d89f3882f64a), uint256(0x303df8524045ca927b4a24fc80acf15f5815c0b4ac33283d35535faa0bb8e513));
        vk.query[14] = Pairing.G1Point(uint256(0x23fdf7c761d6d246db3cd5504d1328360777c5d3cee1192e00eada3db96da644), uint256(0x0b66cc7b383dabea4b0ecaa95989e1515b8cb2363bae7d2f68299c547b8f7d38));
        vk.query[15] = Pairing.G1Point(uint256(0x1416603022e255feebe6a415e5f2b0b8d4dec8f2f9b2b1b622cf96724ecd56e4), uint256(0x0828b33da0f9594a82df77ec2247f08f0785873d8c4e1ae047e58db73b118da9));
        vk.query[16] = Pairing.G1Point(uint256(0x1bca15e50a15b4b98ccbd68d808382523d189d98ab361e36c8217df2d270d9e1), uint256(0x0c20fe5121738ce49dd51da9882abc0b8272800fc7000a2afaf1a48e205be1cf));
        vk.query[17] = Pairing.G1Point(uint256(0x2e605544d5b17bd43c8368473a29b0f582c3f988795380b0a92c6583f6f9a506), uint256(0x1140afd324aeca127816fc7634f740b2eb5d3c3c634394ca3bcf4e27a6a11ab2));
        vk.query[18] = Pairing.G1Point(uint256(0x0afb7c2d984f002ed09ce8c940de64772f4e954ac9d743683906685349a5167e), uint256(0x102cb6d822c2e9854cab142d3557a70ec906e7d22322f931b64d70be2c5ccd82));
        vk.query[19] = Pairing.G1Point(uint256(0x1005ad855470b3204d972d67dd0ef474f3ca2e47198236fc8012902349914991), uint256(0x1ccf055faadb973d10b7cf08a6bff43c0ff81092290a151c0df99335a79ca563));
        vk.query[20] = Pairing.G1Point(uint256(0x1a62be341e523adc7f5f4b23747dcc566e9fd1d16ab4dfe354750e77b6b919c7), uint256(0x22520216292cfaac5caa5d574d91d75ed85947f224e6efce38ca6e305e7fa3b4));
        vk.query[21] = Pairing.G1Point(uint256(0x0889019be4963ebad399d53391ada0514324bc74abf7af1e88b5b2c412dfa920), uint256(0x0168d6062f0fad1e9e16bd704561c693e2495ac708b70e19ee640f252099fbe5));
        vk.query[22] = Pairing.G1Point(uint256(0x1e0e728e10d49dffa734ce1b673cf4349c507f310c924b3715f8ac9148c4ed24), uint256(0x2dae9c4e77b28076a0caac4ce4e14bc0a8521e17defe428887ef4209df82564a));
        vk.query[23] = Pairing.G1Point(uint256(0x0fc707b90c82afc4668065d554db9092816f262f73a510bed7022514b7297537), uint256(0x25a2dd94bd91f5fbfc43fbf7a8d59181a710682ec6d53b974f18b60dff31cabd));
        vk.query[24] = Pairing.G1Point(uint256(0x233406684f626bc3e411ebdb06c1bb0141300b9032efd4dc9dacb1241a5a1612), uint256(0x203d697224161439c2a7f19aa2681615c3cec07c57ec738d3f61067cbdf94116));
        vk.query[25] = Pairing.G1Point(uint256(0x29c4d9d38f95a2d8298065d2202bcbb5d62a60b8666b454d8c4c74372ef0b15b), uint256(0x291d9d3574f30b51f8b1e06c234b4b5aa0cd8c88a9fabac533be71d0881cb2d6));
        vk.query[26] = Pairing.G1Point(uint256(0x257536d8bf66103e3c84e49a1dc7ec67eaccf96da58a9be109de02237e6301d4), uint256(0x026324e7bfb2c1a5ee3f0287417b9e481975bc38d055f1be03212b1535cd37e0));
        vk.query[27] = Pairing.G1Point(uint256(0x2026345d1a971c859eabeac4163ed4c51c9bff66fb5cff326faa3aef4d163139), uint256(0x103665273a145f0abebac1ed743c40a64f2ab5eb12a7193e4bd64893a16a3659));
        vk.query[28] = Pairing.G1Point(uint256(0x1271b9f45a5d02b8c10caa2d29b1090db0b9278da6f1e9784e6d317e45cc5604), uint256(0x153cf09ba9bb63556487f1634a31b085d2bc5ebe6311ca7dd8c72681bee2af2e));
        vk.query[29] = Pairing.G1Point(uint256(0x1de8dd64826e6e24ba281f5ea7669d5ae3aa5c77349f8a01c4b298731f0691f9), uint256(0x2248c208bf0d2f09503d96cbcf28911d83175f83908e28813907749e70994c3d));
        vk.query[30] = Pairing.G1Point(uint256(0x180a3029360455b700d00ddec799a3ee795c7cb3885ccafe366501158c87a5b8), uint256(0x187957db1658abd09ed8e121105899f642c15f6ac51f69f9a1faa1df98f0e13f));
        vk.query[31] = Pairing.G1Point(uint256(0x10811d8b764ef02b35447d1a77f402cbe7832fdffb610e74582e86691caefdd7), uint256(0x1cee7374a371ec823a4eca9834112fa71c49fc7602ae5ee9921ef14a69c256c6));
        vk.query[32] = Pairing.G1Point(uint256(0x1aa414a6271fb25f04c2e477f3c6d61e42180625d0e3a58612f5c1cfb283c06a), uint256(0x2f57772e02afe028320e56e390f8d6577d57f27e2b0cd09c2caef79c41a15810));
        vk.query[33] = Pairing.G1Point(uint256(0x2173128915a20fd9fdc7ccc231fd9a68806a0ac20c734b9494b85407d0cd9f5e), uint256(0x1f20e3a29158b7300ed5acb4d7481e8cc94dd718812fdd3a5eada8a2dd1310e2));
        vk.query[34] = Pairing.G1Point(uint256(0x1a371227e15312af919f86299a7c03d24e5d5f9bb2aebe3444ecb2bdd6da7b3a), uint256(0x026e69652ab0cd96d32c7d3a0b60408173fe1e36d1d4fc454466d9dc3664931b));
        vk.query[35] = Pairing.G1Point(uint256(0x04893f02ea15e366eeaa60e95f9cca8d135b99b2de82aaf9b314cbb696fa54e9), uint256(0x2894841d2925d976157509064603adae5841104d47dc5b88de3d23f7467b8315));
        vk.query[36] = Pairing.G1Point(uint256(0x26e3d09b11887bbeeec9aaac223fd713085030cfc57fd7c34b462efea23f8b52), uint256(0x2dfc00b22e569bedc9337084a2110c2da48db343fecff67b959e33af366652ef));
        vk.query[37] = Pairing.G1Point(uint256(0x11258faf1a1f8a7af263649ed8904375d24c450b1e29b21bac76fdcd2830ff03), uint256(0x2c9a49e272c08d34fd7318e048d8b1701c671bde2365bfdbf972dccac93fc885));
        vk.query[38] = Pairing.G1Point(uint256(0x28620e68b780fa3a461fc72f3c0151075cc8012e9005bd304a7489b11bec6af3), uint256(0x2159d8103b5c98c00fd857f8381ab75f5df4e471f0d1793673412910d144a2ed));
        vk.query[39] = Pairing.G1Point(uint256(0x0257a05d5adb2df923add21410680e8282a896bd95e1441859ea8953a90c0203), uint256(0x0e425f7af1ab20800f3a5921446783839d1073304f6eefeb1ed8cb582288fd63));
        vk.query[40] = Pairing.G1Point(uint256(0x13d7473b7a7bf501fac1f09334ed67f27d897aa1643bff9b6622bc26ee70d5ad), uint256(0x28f032c5204bd2d7b95082df2b371b4fae619cc505a588330c05894e47a54ddb));
        vk.query[41] = Pairing.G1Point(uint256(0x20498e3c5b359fb2b42f4d3ff8d3582d66776c700592e8a29bd5d9a129dc36ed), uint256(0x13fd06c4da1df72ea53790d17c01f01c595380e4007ec76fbdd6b6e9f9a49bf5));
        vk.query[42] = Pairing.G1Point(uint256(0x2f6f3bc472e02db5be209fe2f83685e1d9f48f8ce0835f54b6b6074e0f88b303), uint256(0x2094d2ea32701ee1364c633ec6b3c2083ba5780da34f2267bd3531ac61c58b4b));
        vk.query[43] = Pairing.G1Point(uint256(0x201dc9cd26bf5a255c2d3301d03512b2779fa7274e122efa74892032b348fa36), uint256(0x28efc92390226feaf1b9a1c4a412a497017ad1b239e0f36c5b242a0bc87662fd));
        vk.query[44] = Pairing.G1Point(uint256(0x0e9f384c9bde7ed1429eaa9182151057f95c39491c82ffb3c21e7422907cdef1), uint256(0x0c34b37bca40625acecd5c9d2b5e2715d0a02515931557431bab162fef1e19d9));
        vk.query[45] = Pairing.G1Point(uint256(0x163aee611238adfd344330091c4c5c6cf6dd8ed9888b22609ed08bb124fa053a), uint256(0x02642dba20d55870cad3f6dee2925f8b6471da93fb969da1fb3776e71fa997e2));
        vk.query[46] = Pairing.G1Point(uint256(0x27d559ac5f91aa07e9f798507e24b54250dec9cea089aacaf82c9d0378b1e8c0), uint256(0x2e9fa5d7c3c90e8b7a553e016444a071381855889de5b3f36e7086ee9d6e18c2));
        vk.query[47] = Pairing.G1Point(uint256(0x12f6a98e673d9177eba02ea9555a2ae427b163384f570482a08b83cd8f666b55), uint256(0x27493132bc05558c9e9bd4aa3739176221299e2ea7777a2bb58747c9549accba));
        vk.query[48] = Pairing.G1Point(uint256(0x06fb511334b82bb79a393cfb5c7d8ee5567796fb5b909bd7ffc82cdfea271e09), uint256(0x05823e7e71f26f3035f5263f58154733170ee356ccdc8bb94e73d6d9f1d6edc7));
        vk.query[49] = Pairing.G1Point(uint256(0x0c2f31968178725904df921a9f02bdbe4d9c12e01d45ac95ecd46ffa0f79499a), uint256(0x16093413f959f22bec334661055b01c5b7cf1568bcdbf55ebaa53f100395216d));
        vk.query[50] = Pairing.G1Point(uint256(0x2aa3297934fdc62f6ff4cf058ce8ac535924ff90463f0d6735572b1243d57a3e), uint256(0x18bea401406a67ef445abbeb22a25811a21ae4fe3e148322e1740b6180b8985c));
        vk.query[51] = Pairing.G1Point(uint256(0x242cc9e6b247aeda512d31768d51956a16d1d84f878c424aed148aeda285b5a7), uint256(0x25e7f0674ab6d947d4ebd213a3437314b75e7a42d5c76a2490779b6b1bf75af1));
        vk.query[52] = Pairing.G1Point(uint256(0x1876292010cf276a53e9f2cd3968de1b54487016c7935fcee2624085e4d49a29), uint256(0x1249778430f44aa76e5432ec32bbb08bbfe3cc6112ff80b56ae8049ffd060a14));
        vk.query[53] = Pairing.G1Point(uint256(0x271e3b95445aa0877fb74fa22dfad20c39115a5ab11106cbe61766dfe5f3b965), uint256(0x20032c57eb67402291ff44388b482b406122015d999ba47421cb81963feba789));
        vk.query[54] = Pairing.G1Point(uint256(0x05eef2280a6369ea73932badc8f0eb7534d5107122fc31bd109c160ea93eda84), uint256(0x1470ffb1a74e6e0bb96dd9cb93c8f3de544b5720a32e9ab5d4e4d67bab59e1b7));
        vk.query[55] = Pairing.G1Point(uint256(0x08b491d04eec1ca2758580242fd640088afb257e23c2c4ab98895c27b969dcd8), uint256(0x15c29c73a998aab7764ecb9a8e10df8fc004908bfab98cc9c6abd497628b0c73));
        vk.query[56] = Pairing.G1Point(uint256(0x0d506463f8189ae138171b6882e3146ba27d85759756ee384ac9d95d2e52e445), uint256(0x2f2ea34b67b3b437bf97aaf533bd98e153fe603def8683831b9903b480b3941a));
        vk.query[57] = Pairing.G1Point(uint256(0x238aeb731792820a3b64aded10754cb63ac0be359dd43eaddd50e6f9b406f4d3), uint256(0x08c4a635d12e3968c72776f828c7cfe643012fda9172db8a1fc09babd5d59463));
        vk.query[58] = Pairing.G1Point(uint256(0x09f0699b1466407bb026032c1aa0a268d7978d5d12e10aaf50b9c4fd7a962066), uint256(0x1b2dad31a2d4edec6fb6c78c07204f71ed6b28ae870de1871513e277e9a67c3f));
        vk.query[59] = Pairing.G1Point(uint256(0x247b1c64bfdb167dd44eb64c2c03b39303396be69b23da8609b812a6154875fd), uint256(0x0f59e59be6abf620f3445945d11ea6871f598b0b8e1e5584eb247a4167a250d8));
        vk.query[60] = Pairing.G1Point(uint256(0x243f87ce3958aff514facab146c2a58d2a3a786f20a1d7da86bfe364425ebfa0), uint256(0x29d58c6bbc8309892df435ee7012e067b77194fba6a694f5aed1f7d0422686ab));
        vk.query[61] = Pairing.G1Point(uint256(0x2847ef95870a41d346befa7eabd4a76417ca2e2829643179f1cf66794c694998), uint256(0x2f913ff8484f10f7ac45e46ecea44eff6fd9dde6068e92f18a93b64bf96f5ca3));
        vk.query[62] = Pairing.G1Point(uint256(0x008c5482887eb4c44cffacca6c396b7540cfd03e69b2b0aad9c3d62270a3062e), uint256(0x118a1f61badfca74aab5a8deef85b5e8fcd3196548b6812e5ceef2622a33da5d));
        vk.query[63] = Pairing.G1Point(uint256(0x2a59d4f00353c4a12047f83d290ebb448784b5bb13fcc1399369f755f085009d), uint256(0x2d52d94b43ec107739cedfb0350b374d1fc629b0e7d580974592edaf943dfecd));
        vk.query[64] = Pairing.G1Point(uint256(0x22c67f00fcf868b6a39a30c78549ea0aada6611189ef31ed4ed22a16bc5adaf9), uint256(0x3049226cbf160f866d8fedaf3e33cba65688613d74c7d7d580a1708faa27ff70));
        vk.query[65] = Pairing.G1Point(uint256(0x240f33a15b8e53ec53502a00f92c059f6fff753718bf18d2953f696db28d9a06), uint256(0x0cb7a3eb69f821632c8b254dc501144aa14c0ef3d03c8153b1b257b3ce61c8bb));
        vk.query[66] = Pairing.G1Point(uint256(0x0a47ebef4dcdd31c634dba600fbc228cb18dfd22a9fcc6b999cca86052b81f6d), uint256(0x296989e07f431c0891861ece2d696915d36adcb78832a57ec959a8059b0acff5));
        vk.query[67] = Pairing.G1Point(uint256(0x130264195e2db15772c712f70b6b2d615851c207a09e6be86ff220dc384a463c), uint256(0x2e0abaeb538277e9a8b5bf37ba20f027b4db23dab96e3cf20cf51f9dce41a351));
        vk.query[68] = Pairing.G1Point(uint256(0x0fae2cdea98b8cf064ffa55f4ca4a87703123dbd3e3e1371e688d237c0d941f7), uint256(0x2072671512b7288b58dcdb67042452faa814d4f6df10a0e8cd51191109bca47d));
        vk.query[69] = Pairing.G1Point(uint256(0x07a2b17f5684a8e5b67df2a253be6a0349cec2c627135fc504ee9fc1c6fba47e), uint256(0x2a800af73b4bf9ba1e3503b86f46800973a72693a09a0674130ce20a7c50c6e9));
        vk.query[70] = Pairing.G1Point(uint256(0x136b1c5a7013f21ba3d64087f3e35f55fb08f38508d9993ead69fafeacd6ac3d), uint256(0x21117ce4b295a8d1a37a7ade33a8b6ea5d5e4f2e889e7fc50b97aa1e88d11193));
        vk.query[71] = Pairing.G1Point(uint256(0x1efca38cd2abefb2fd978b837eb355ca7094f4f3a43e7b10bbc51963da76028c), uint256(0x0aa5c123b6f5f77a8851c37d0f547e95dc533ccf192c771e6195962378e9fbf8));
        vk.query[72] = Pairing.G1Point(uint256(0x1a774600580732865f1a4625befb2817aa20b3725c5069c24d37f4e391ad7f13), uint256(0x1a73f3708bae5fa962feeb9576727a1a9922fc87e1c455f6f70c357a31a65c64));
        vk.query[73] = Pairing.G1Point(uint256(0x2eafd91f33b480c610d2659df804cfda3d74eb625829111a2a90a2b04af45f16), uint256(0x0c9d279d5d6b88438a9e524cff72f5b7f02e7a1fc9578dc66df20676b6be73e5));
        vk.query[74] = Pairing.G1Point(uint256(0x244d3ebc51ecf2466068480a9d1e42a2b9b602adcbd1ef432bdd99f502185e48), uint256(0x1c5a5fc629f77ec98766db4fa55541261f874f2cfe70a5e750d406fa3b9470ea));
        vk.query[75] = Pairing.G1Point(uint256(0x1cd4d166ccc4c717beb4d421b79f12b46a8c94e980f263e01d4fbc01fae736d4), uint256(0x2031076903f87529c35005a5e26f3c095a6cb4db76cbfa1926b2a7ddcfd8c24b));
        vk.query[76] = Pairing.G1Point(uint256(0x0d4bbea9123ac8272dc324b1b232649320b38897f8a2139913955b7fa2344d48), uint256(0x24b5bf927466a49cd8587acf0204fea666ad4fc70ee4d6a9156616346362bd97));
        vk.query[77] = Pairing.G1Point(uint256(0x21fd5b63ca20937698b222190308901647abde6e2b022331f93a80aed58b8180), uint256(0x13b85e8eee66dfcb6cb9308627b1b5a703f527c16de84e20af2d10a48f593b67));
        vk.query[78] = Pairing.G1Point(uint256(0x1eb5c53cc507aac8ae7569e1f6a884e4f80d8303a50fd690567ba4b7194b2a5d), uint256(0x0e8667cf13c67307097c0837d76ec70ecc5d2605c8a5016e41ab4451b769569d));
        vk.query[79] = Pairing.G1Point(uint256(0x21eadcba309fe52a29824573a59e2911eeb21147a8af2abda73fe9a182f21ec9), uint256(0x092429984d4a5de590415da7f219d14c91d78ffd28db010d71590037e1dfc03d));
        vk.query[80] = Pairing.G1Point(uint256(0x29c2b01bd8bf144d6b7c80a447b2beb8e596bcb6fdc43f4c1df1b186e2a9ca59), uint256(0x1e7f69d40d764b8f4e257ceefe5e72f1cd770f8808f78184c2cef46cc286b657));
        vk.query[81] = Pairing.G1Point(uint256(0x0bb2d971740add216d7c6bf5df557efaeeee38d80de1973653c80ef6a2e03065), uint256(0x2e49ebb9eec385c1d311920e89dde702583656a4013faf744df3676a32db865f));
        vk.query[82] = Pairing.G1Point(uint256(0x0082cf11e1cd70c5db12e7050870692fa67ea873c56471316ddf8baea5b6d1c5), uint256(0x29c4706a0b9147120500b9baa4504ddfa4f4fbbf2ee8c06c71be7e3e2e75d3cf));
        vk.query[83] = Pairing.G1Point(uint256(0x0b1a95ccc3c0d7df9331d159543d073380256ee613bd5d053a731b361ae26ae8), uint256(0x10a612dc42e911365f7068bad68ec7da9b2f6e4d06d9a25af85ffbe7a1411c25));
        vk.query[84] = Pairing.G1Point(uint256(0x2128aabe9106e61562fe8bb038beaf5147e9ba0344de6f0c825860abd20fe118), uint256(0x1466e5183158f881275345c21517666984e63493079a6857488b948fbff3c7df));
        vk.query[85] = Pairing.G1Point(uint256(0x0abafd4f2a6acf5f7718a98a97d64fc06ae2cc1d50e78dfc782513cbd8a1d915), uint256(0x060305dca6732855f6d5765e92ce8e2cb2dfe53cda91927c4f14c074bd8e8dce));
        vk.query[86] = Pairing.G1Point(uint256(0x138970b2d409fab4527ff2f5265d2820ccafd28cbb588b2c318d77e6a686869d), uint256(0x0580403ebf689e3843558d39bb8970ac13efd88b464301a83e55b024454fdcd1));
        vk.query[87] = Pairing.G1Point(uint256(0x0b8e3947e6eff5de92ce37074d3a721836d0b8969ff08953a3dd2c0c26507993), uint256(0x1c31c928a213915cd882792b51c6f448d4abe093bd8ed2c5918e7220ff4cc9f1));
        vk.query[88] = Pairing.G1Point(uint256(0x2818d0373531a000a35f2c0ca34af97c04bef73fee4c679cfde4711e8bec66e7), uint256(0x13aa6f15e2af87dea99030d9d3c869870f1d6c7161a1cfe786874c194b7d7d21));
        vk.query[89] = Pairing.G1Point(uint256(0x2fa3dd63e30cc3e400033d1021c5094f1955c2948f48b197d86a1b364c1211d9), uint256(0x220660933b6f9dc3b9a462a0631f454b5e1d92298351b6b8e3ce11b81ca13d8b));
        vk.query[90] = Pairing.G1Point(uint256(0x11ed2034918782525d47df007fd9a2e5df329a3ca84cbde7de3cd9a9c8624ac5), uint256(0x07ec114d790c9c85434e6a2b9d54c22b5b631a4d7c9de07c6f602535b0185473));
        vk.query[91] = Pairing.G1Point(uint256(0x0fe00b4e255e98a4d2838634a492354eabf8cfc5920a5fcca888c4885668acec), uint256(0x0c662b2d6e0207f64c1b6d056f4ebccde4b16581f96c13514f9201f4c08b0686));
        vk.query[92] = Pairing.G1Point(uint256(0x1cb5ac904c9b23c6a2829a0982941c46a214cae15b3652b65125d001e2bd6285), uint256(0x1a7ab3c4a8b80cb2d835e6cf4d2f74d24ff65bf8f64618d0c39e008e2fa8dd5b));
        vk.query[93] = Pairing.G1Point(uint256(0x0b291083772f0a2dd2afa4f0f2e5ccc24854d3fa7c42b560606f8dbb751a9f7b), uint256(0x1f49a9d73c69bf90c3d73d387b8a6ccd0e3079e44313dd1b94dc3ae255739ec9));
        vk.query[94] = Pairing.G1Point(uint256(0x06369a11a95740ea33a03014594a572ded0e5e8c9429c2a5c517f497a215b4ff), uint256(0x0395ccd791531351cdc3e20589ef57d67b6792b2fcacb4862f695cf2e6b62806));
        vk.query[95] = Pairing.G1Point(uint256(0x1b5ca94b144f801765c95e25b0c228f3b07bac91fc3416a61381ef4b7a12bb59), uint256(0x0791c6e7e8766d60e48a1361ad390ef7a490f7e8dd4cd494a63bb0422328d702));
        vk.query[96] = Pairing.G1Point(uint256(0x242502c61c3a225ae25725e059d81e8bb13ae9a9ecabe6b9f0d705db9b3b6640), uint256(0x2f2aa6be4acd36d6d9735f74deba47bd86bacac8b139dc944c98c39e394b4da0));
        vk.query[97] = Pairing.G1Point(uint256(0x2827d70aa9696286109a138260aaf1779975b08b216dbabb1b4ef72ab0e062e5), uint256(0x0ca8c262531c50f5738a4ed5d7689b51f9ccd2c9583bf0077e7f8ff0dcf2d84f));
        vk.query[98] = Pairing.G1Point(uint256(0x2f13230e61d764e6382867e013cfa2bd80ca6a949d4e2f60a6c4d0a9f1b16042), uint256(0x061556f59afaa7c2a4b2c1b400ab7ba33dda9958d6f482644c65feb3842453f6));
        vk.query[99] = Pairing.G1Point(uint256(0x121ac0444e47890342294798fe27cf2a850b36164d63effc413f8ff31b925a29), uint256(0x23984b2561d36dda3c0ebe355703f6efaeacf049208c5bbaacf31a1d7bc62437));
        vk.query[100] = Pairing.G1Point(uint256(0x1471c073d6c7d5c6d20c99951d1520ff1668ecf9e759f1e6c7d97b7dc7759d49), uint256(0x043dff26086d73c26a634b784805d8fdcb145cb6e3b6c3ecea2c5e17b7094c6a));
        vk.query[101] = Pairing.G1Point(uint256(0x09bb75f8644fe1da9dfc8205b8caee1dbc14ef66a735d61ff7344040c32ba94e), uint256(0x01d73d6fcc6fe634174315915a9c0c47f3a9f6cb1b5ad3e54893ec4630f9a6dd));
        vk.query[102] = Pairing.G1Point(uint256(0x2ed61e235be2dd36790bba054c32c0c7fa1be9afa9b64d4abe17bb11024e2c26), uint256(0x03eafd18280c2773fc9152c4b31b9fd9339f2159fd636fb236c9fda875ced15c));
        vk.query[103] = Pairing.G1Point(uint256(0x044f4d7fbf264e9ccd84b4214c94d7744b64f5db06ccc77613fb692cd8ee5ce7), uint256(0x0ce48e0e1186db1cf377a7a82cf9490e85f2026f7142f5463da06c206aeb8f1f));
        vk.query[104] = Pairing.G1Point(uint256(0x13106c5f15c9016ce193af93a21c16227b16da45739b7588c7a5fd3118d27ce2), uint256(0x0ef424b27cfc8e60557ac24b3f224c860350e815bb620d702b1204cf124ae71d));
        vk.query[105] = Pairing.G1Point(uint256(0x1cdb3b81b266f2d652b936020bf4f13542f3d6debb70b3b1ed6665d99ca9ccc1), uint256(0x2b66ed500c456d4cb371b2a8c4dd5546773945f7f28ce1ced5201edad7997860));
        vk.query[106] = Pairing.G1Point(uint256(0x0e885173c6bed742e2b9ad44b3e168063f0d51f0e3acae6f9ac4171a587a1309), uint256(0x3007840133a3309354855ac854388e013ac3326392d2c6428a549d939e676f34));
        vk.query[107] = Pairing.G1Point(uint256(0x0c545f4acbc89cec0f85404627c170aa25d76969a301dc3199136b46703561a5), uint256(0x0cae19ddc4f1222ce72ff281a00ff3bc1454dfb966a017e0b37290ee2fe371e1));
        vk.query[108] = Pairing.G1Point(uint256(0x21d7f95a082b152d2d8ae3db753e8705124d8d968e4a82d934fc5d01a3dca836), uint256(0x087f4d2d2bee646236301ef58f89f77c64dab9d59c10e1a334b476b88e29938b));
        vk.query[109] = Pairing.G1Point(uint256(0x10939a34ff464b97ce8b47fcef5707b1580134278ec8bb1e3008553001e54f82), uint256(0x0f7eb5d361b22f89507a190f0422ddbc36f4e467199fae400da3053829970290));
        vk.query[110] = Pairing.G1Point(uint256(0x27d09e22cfa5650b8635b2aba541d2325720526b187975df3930d01509d6f3e1), uint256(0x25fcef4b628e91c35e32fef800d07c9ed0468c87a13d25d65d24bf2f1d92ed1e));
        vk.query[111] = Pairing.G1Point(uint256(0x1e09eba4545f5bf577d1b2fe5a92afcdc6999cd812d3abebc8e53c35fd4aa590), uint256(0x2ae49a0798a1bc3e9aafd08ad8329289df99928555dc905493f3c46956fc656f));
        vk.query[112] = Pairing.G1Point(uint256(0x20e21c55cc2404938296393166f4907797b95ad40ce45e1b81b3f2225b802b09), uint256(0x129d14c2d8e56413c16e6802d67b1a9a14aeee2566a88965d33683dba546d657));
        vk.query[113] = Pairing.G1Point(uint256(0x14f79087b043179396047ed001446f4e523878a9fe99acc13f91ef4c1021400a), uint256(0x111c53ca339892fad0a1d0078d85907a14e87baacfec1a6a31e553155078820a));
        vk.query[114] = Pairing.G1Point(uint256(0x21f0986023c94723c66820ca492abf30ab6ee3b63bd598ff8d9d179d2f608bd5), uint256(0x2091fa7cf54dd36ca0dfa8d9431ca51045eec8e4fcc0c48f87e0f010b04b7ef3));
        vk.query[115] = Pairing.G1Point(uint256(0x302941254e130079095338186a088a399f8c04141aeddfc9a4e7a24f594a0cad), uint256(0x30254cf1725c2dfd4f2190021be71e43dad8ff8fe628dfc6dcf6d1a313adc9e7));
        vk.query[116] = Pairing.G1Point(uint256(0x00fae1e95a300dcb37936cced8d04722ac08b896c2a0677824669df5c5e9886f), uint256(0x0b2d7939f6ca39382e6f05706677157d07563ac10317bd08c54921fb508ff69f));
        vk.query[117] = Pairing.G1Point(uint256(0x2814d6ad29a9aec1deea7008e2ae8a3eab743cb4899cc7899dd6706bf87d05cc), uint256(0x15a03ae826b5db49f79c9390ccedc4efde818360691966e5cf48f6083c5e6128));
        vk.query[118] = Pairing.G1Point(uint256(0x0dc45fb13d2b55accdc9a6f40d5031b48bea9783b7a1be2ea9c3227342163071), uint256(0x1bb9fb69afdf0fc3ac701abb1a6156b80fa5fc0208ca9c0a24aa758e43e17034));
        vk.query[119] = Pairing.G1Point(uint256(0x22a3b49280dc0adb5e9b5e6ba4ea153f0becbf764502e9e2489f8b3d5f36faa2), uint256(0x1b99e65903a66785bd190e91385433ddad071402210dd37483a3b4f379899fcd));
        vk.query[120] = Pairing.G1Point(uint256(0x092ba454277d833e6fb4262b27262cebcf5a00bbbb647743016dcb8d6f9a3180), uint256(0x12593a918548adfae07399bc55f525d15cb5746b5ba74b68c43aab4fdd8204e0));
        vk.query[121] = Pairing.G1Point(uint256(0x199e41324892d70cf7b1687cdf6f631d341c0c3f1e41a4b7ed4d6ec7159ce138), uint256(0x22997a3caf0ce14b1186161724fa59ae5c47c15c944d64b0ec39b31a9e98ed38));
        vk.query[122] = Pairing.G1Point(uint256(0x2d65f69c9633b4e39785e3dc2f88c2a9fdd4f3aafb09cac66703b86c0e89c573), uint256(0x23e5ed2ecb68c8de0b3ffa935be41a8ca3f62ad5f9065e9248460854eb1d7dfa));
        vk.query[123] = Pairing.G1Point(uint256(0x093e875c1705a8e17fe25231aa314e07855706b488827ce2d793ace630840a50), uint256(0x16fb85620985c2fa1a9831a155cd6b18a72889ac33f3bd8be92fc410aed2162d));
        vk.query[124] = Pairing.G1Point(uint256(0x2367ac678aea5d80b7d85e69508f11075976ffde14f01430cfc8b3cd4909af30), uint256(0x1287463857243cc60c9d648576f2981cd3e00707dd2ac577ab0456215963d833));
        vk.query[125] = Pairing.G1Point(uint256(0x0c5a3c460a071bf4e5d3089be8111f854765de4e01e2cacffe5c97a394575285), uint256(0x2be99b9e99e2be0694d31f9525e254a478fa8f52c0c6feb24d46b96a5a0486ec));
        vk.query[126] = Pairing.G1Point(uint256(0x274ca959350052bee71abd859eda058f051855780543797ed42360d89031135a), uint256(0x2f050aec2317cb47d9cc6eb9e19bdee3a4931c3ee40b10664ec67da26b417cc5));
        vk.query[127] = Pairing.G1Point(uint256(0x2e1f444946e3ab11203581352bd90b59c462d5c1ce7667503c822f99fa5ae04e), uint256(0x17ddc83935a1f9878906c1fe243d85593afe7fca9852822fbcb2bd8e950884ec));
        vk.query[128] = Pairing.G1Point(uint256(0x2902c33ce1dac98e1333fa369fcdb9ac3ba15f4bccf7d1b8a0fc9194e06adc65), uint256(0x21d74ab5fdf6a20a18500b7797c04f3aed87d7df467c8fc7dc1c26dcb36feaec));
        vk.query[129] = Pairing.G1Point(uint256(0x254dad4c3fbd39e5af29b58931a6a94a4267f10a1becd1fc1deca82ffb53affc), uint256(0x28b1bcf19dec1805edc2180f99803d9cb18f5a1c99a73e7b3ea3b457590ddde9));
        vk.query[130] = Pairing.G1Point(uint256(0x00987eb300a2b9b7674bd6b28b4e154a14e4ff845220aa008747408e5666b1a0), uint256(0x167aa7b8eebc88988b2e92017392056a1c310bab729242395aca41ef688e39cb));
        vk.query[131] = Pairing.G1Point(uint256(0x2369f430fd8393a0402a65bbc899fba63c334903b401574c6c3a4639657d0b11), uint256(0x1e6deb61270a65c0974f6856fa90d0471906c7f482eacae5be195b6d19e09261));
        vk.query[132] = Pairing.G1Point(uint256(0x23a3df7a7f4f723bf34964e951fc33160a898bc2ae02873723b4f73589879860), uint256(0x1c30a79d242952c68716ba70cd846540f0ad37b38caaa2a5bd6a4ef4c9565d37));
        vk.query[133] = Pairing.G1Point(uint256(0x0ac4e0ab7dd5b8f9097bae9193b4800c7414d15be80fef64143a282bed0bc8d6), uint256(0x10606fc68d15bf11fe7c5a8c10b1ee091b5a4144ce0b4b7bf655807de48e5594));
        vk.query[134] = Pairing.G1Point(uint256(0x2b283dd5f318a8875bc52a02e26827665bc51cfd3a8410d5e1e99e9ccee43e2e), uint256(0x1522ae33f0eb7faa1920d1051d6083b1c8884216ddb02161056194225fed1499));
        vk.query[135] = Pairing.G1Point(uint256(0x21eed7a7e34d53a20ed6094f87195f372cb980861d0338937d9dfc0369131945), uint256(0x26b9f43b58b21bd306757642abd5866181ca766ecc5d2177836acfb8dbec2ea2));
        vk.query[136] = Pairing.G1Point(uint256(0x23b958a58159567640c90625ace343b9f51e80c27647078c9ebf98c5fa28d368), uint256(0x0858d2c4477942394f8ca6adac66441791d04e38e2642d5c4c01327544e72b13));
        vk.query[137] = Pairing.G1Point(uint256(0x2eade7f9acabd8d854c7ca8567805daa6f5854885e547591a85869a1ccd3ce42), uint256(0x10fc7023c42c81d4ba439ad595081c3c30bd70d35823bd8c71a88d3f61bab414));
        vk.query[138] = Pairing.G1Point(uint256(0x0801d665f60919e1801cc063ef157200133574bf467e24c6a88f399b918a204e), uint256(0x1f78e87d2b09d31c96f2488d32f2d6d82f1920a90a68121a581d5d98f434df1f));
        vk.query[139] = Pairing.G1Point(uint256(0x2d4d959c50879f2e8556bfbb0c8f4d7ae677cc822d7601e72e768d96aee87411), uint256(0x008cacf79aac8b85b4e42dbaadc1b3eeb6468a48367447e5bc2f35717eb100ce));
        vk.query[140] = Pairing.G1Point(uint256(0x0c92a784372afc4ca7e4f1b5b613590eb720cb912c80d8ab49c10ab19805d45b), uint256(0x02b9ee4cb076ccda7c2892079d7d5601894e90a1b8abcdc8e3a5353f93cf73c2));
        vk.query[141] = Pairing.G1Point(uint256(0x100ad59bef4522c40cb4453b3b56eacf4e96278226a60524f230a388f72e18bc), uint256(0x09127a7ac789f2053ddb49c79d4a2321cf3d959e23ebd30d6b9c568480b82df5));
        vk.query[142] = Pairing.G1Point(uint256(0x1c6c9d811ae18c6de232d70d00a303dd931ea6841aefc27204d19f1c70418feb), uint256(0x08c61c761ef5f0a25b5b43ea235dc6fd9350e4c2b14770f828ac3363b7d6cae2));
        vk.query[143] = Pairing.G1Point(uint256(0x2de5f22f01c43f66f68274001075cdaaf24040a0b81415e94492f1d246390099), uint256(0x17c2e660c32f1fc246a8a764467b01a8f04bc31100b6c90b8dd0de6d09e50ce6));
        vk.query[144] = Pairing.G1Point(uint256(0x242206eeac9a763885d15c44d5e057efcb9ea55c5b7b6c54fc901d189c9ebaf3), uint256(0x2e3efa532980e222ff4f141decfa123dd2437c662a31396ffe16fd9952f0da50));
        vk.query[145] = Pairing.G1Point(uint256(0x1f5d6b3b60e1de9d8a4a86fc064b99599b100f8c65e7a082b71ea148d23395c7), uint256(0x115aad1032fb66e6a34109caa00829d95c1ba354f4edb878f64259cc31f0e3c2));
        vk.query[146] = Pairing.G1Point(uint256(0x166bffc574abdc5d0146f67ad694efb499487f7c973916754d608e12e6b1b944), uint256(0x2db8a242d1957274df01e06c673ca7dae625606a7df8cbdf35faae8cbb44d07e));
        vk.query[147] = Pairing.G1Point(uint256(0x0ad282cd91dbe5b04b508f991f68c3a711d7b640f37836870e01aed9492e0e4d), uint256(0x26e1dd363e34d5846132b5316922732b44ebb1bf3df886b0f262b5c63a1d319f));
        vk.query[148] = Pairing.G1Point(uint256(0x17922029bebb5973d1135a1df4c923d0ce68cc441d6a0f757219245c03664c22), uint256(0x183c875d18c48935268f21161e61865d80c994ae5c44d29af22b46c99df166d5));
        vk.query[149] = Pairing.G1Point(uint256(0x234b8ce2f5225a67520054a1d1c2993a2cf9fb09f7bb7e387c48088abd46de6e), uint256(0x0b6b79c28d3b755a8104f38740b96034ac9013d1358bd10f0f07efb1ae925d97));
        vk.query[150] = Pairing.G1Point(uint256(0x0559159717d663e491dea31e9b2f50010037f6451d2cd0c7368cbf43ad58528c), uint256(0x209fc559da149520963eb3c115c0df6dc739bf874038e3ff518037d4719259d7));
        vk.query[151] = Pairing.G1Point(uint256(0x29ecba93c142d794e01309f9634f09f431356a12c1a53f9da0c5b9c9df9ccb2b), uint256(0x2bc00ad3a86fc9159e68c99435d80d3aa77f65083826ed3a6b8c6ea7d79675c5));
        vk.query[152] = Pairing.G1Point(uint256(0x0d6aa2e9ac61d255003749e3d32baf7a7213ad52448fbb85e7bb7cb2279c9887), uint256(0x28e1be23dacf06e91bc17803d8e7f4fbc7d8b3a71f16a64f62dbb99def12f607));
        vk.query[153] = Pairing.G1Point(uint256(0x26789a4b10d69fa89ff1f7bfd3b6ebc29e168b12aa21623defe021069c3c7c1a), uint256(0x09dd8ab09ec7141fa4e2fd7885fe11e63241f6a4c8abc1da252e3b17b0a5346f));
        vk.query[154] = Pairing.G1Point(uint256(0x1eb1d70d3c3c97b9cc45e4501e6c0fc03b80efa0c23fcfcf3dcf01078342dd61), uint256(0x0b1ea0098b9024562d8daeb2ef8404b7b02a96661a4d71c82a6acba4a77a8863));
        vk.query[155] = Pairing.G1Point(uint256(0x1092737ec904a5be3edf12e78efcfaef52e79d92b4a119745f66b6ee69fff6f7), uint256(0x17ebb77afe3e98080be7208eea5a0fe946794dda9bea34b27e70aed7637b6e09));
        vk.query[156] = Pairing.G1Point(uint256(0x0b18b3f2bec70135f29070d9f669f24ae67bb39881224a68e3da254daf991e9a), uint256(0x1b74d7b17a5170c5fcfd26b34968a54d498728866722a13b7b177728f8c677f8));
        vk.query[157] = Pairing.G1Point(uint256(0x23fcf33270846fe79c120a08c236f94ad59af344c661c85fd1f2675099172d8c), uint256(0x1ef933092340b057631642fcad826b9bf0ee4d048bbc5682385568f846faf2e5));
        vk.query[158] = Pairing.G1Point(uint256(0x24b87cebb10da951e8e9502e909eebd0b2420c4ec0580f1bbe1b4cbd4fe4637c), uint256(0x1706708130019cc3a08c1e779e0b8c263a0f02138bb111087784f37bd828a31b));
        vk.query[159] = Pairing.G1Point(uint256(0x11110a0307e3fd09dcc22eea4dd2b5694e515287099b87f5628d5847fc23549c), uint256(0x23d0f8a574fadaeafc59a69e521d4e821d2805fe230255b2d40700f6ae569322));
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
            Proof memory proof, uint[159] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](159);
        
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