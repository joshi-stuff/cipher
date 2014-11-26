// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.test.test.padding_tests;

import "dart:typed_data";

import "package:cipher/cipher.dart";
import "package:unittest/unittest.dart";

import "./src/helpers.dart";

void runPaddingTest(String algorithmName, Map<Param, dynamic> params, String unpadData,
    String padData) {

  final padder = new Padding(algorithmName, <Param, dynamic>{}
      ..[Param.ForPadding] = true
      ..addAll(params));

  final unpadder = new Padding(algorithmName, <Param, dynamic>{}
      ..[Param.ForPadding] = false
      ..addAll(params));

  group("${algorithmName}:", () {
    test("pad: $unpadData", () {

      var dataBytes = new Uint8List.fromList(unpadData.codeUnits);
      var ret = padder.process(dataBytes);// addPadding(dataBytes, unpadData.length);

      var expectedBytes = createUint8ListFromHexString(padData);
      expect(ret, equals(expectedBytes));

    });

    test("unpad: $padData", () {

      var dataBytes = createUint8ListFromHexString(padData);
      var ret = unpadder.process(dataBytes);

      var expectedBytes = new Uint8List.fromList(unpadData.codeUnits);
      expect(ret, equals(expectedBytes));

    });
  });
}
