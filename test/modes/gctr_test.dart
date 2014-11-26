// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.test.modes.gctr_test;

import "package:cipher/cipher.dart";

import "../test/block_cipher_tests.dart";
import "../test/src/null_block_cipher.dart";

void main() {

  initCipher();
  BlockCipher.registry["Null"] = (name, params) => new NullBlockCipher(params, 8);

  final params = {
    Param.IV: [
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x99,
        0xAA,
        0xBB,
        0xCC,
        0xDD,
        0xEE,
        0xFF]
  };

  runBlockCipherTests(
      "Null/GCTR",
      params,
      [
          "Lorem ipsum dolor sit amet, consectetur adipiscing elit ........",
          "4d7d515125760e0871664915283804167134565f2478081761610a17373604086075535d2c2f195c67734149"
              "35280f14697f095f0c35195e263704154a734051",
          "En un lugar de La Mancha, de cuyo nombre no quiero acordarme ...",
          "447c034126760b0d6572561528324835623468573e3b011b28354252743a1f026a3649573538191926794719"
              "2d2e05187577095b03331f1a696b475e44734051"]);

}
