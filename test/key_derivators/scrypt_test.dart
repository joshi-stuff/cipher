// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.test.key_derivators.scrypt_test;

import 'package:cipher/cipher.dart';

import '../test/key_derivators_tests.dart';
import '../test/src/helpers.dart';

/**
 * NOTE: the expected results for these tests are taken from the Java library found at
 * [https://github.com/wg/scrypt]. See also
 * [http://tools.ietf.org/html/draft-josefsson-scrypt-kdf-00#page-10] (which at the time of writing
 * this test had typos because it interchanged N and r parameters).
 */
void main() {

  initCipher();

  runKeyDerivatorTests("scrypt", [{
      Param.DesiredKeyLength: 64,
      Param.Salt: createUint8ListFromString("NaCl"),
      ScryptParam.N: 1024,
      ScryptParam.r: 8,
      ScryptParam.p: 16
    },
        "password",
        "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d"
            "9830dac727afb94a83ee6d8360cbdfa2cc0640",
        {
      Param.DesiredKeyLength: 64,
      Param.Salt: createUint8ListFromString("SodiumChloride"),
      ScryptParam.N: 16384,
      ScryptParam.r: 8,
      ScryptParam.p: 1
    },
        "pleaseletmein",
        "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d4970524"
            "2a9af9e61e85dc0d651e40dfcf017b45575887"]);

}
