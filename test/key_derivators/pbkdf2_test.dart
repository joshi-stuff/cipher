// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.test.key_derivators.pbkdf2_test;

import 'package:cipher/cipher.dart';

import '../test/key_derivators_tests.dart';
import '../test/src/helpers.dart';

void main() {

  initCipher();

  final params = {
    Param.DesiredKeyLength: 16,
    Param.Salt: createUint8ListFromString("salt"),
    Pbkdf2Param.IterationCount: 100
  };

  runKeyDerivatorTests(
      "SHA-1/HMAC/PBKDF2",
      [
          params,
          "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
          "12aaf52b2fc239db41778c59d0e3c927",
          params,
          "En un lugar de La Mancha, de cuyo nombre no quiero acordarme...",
          "5b78b99ac2cc6b6626558f53c7490f4a"]);

}
