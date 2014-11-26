// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.block.base_block_cipher;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/algorithm/base_algorithm.dart";

/// Base implementation of [BlockCipher] which provides shared methods.
abstract class BaseBlockCipher extends BaseParameterizedNamedAlgorithm implements BlockCipher {

  BaseBlockCipher(String algorithmName, Map<Param, dynamic> params) : super(algorithmName, params);

  Uint8List process(Uint8List data) {
    if (data.length > blockSize) {
      throw new ArgumentError(
          "Data length (${data.length}) cannot be larger than the block size: ${blockSize}");
    }

    var out = new Uint8List(blockSize);
    var len = processBlock(data, 0, out, 0);
    return out.sublist(0, len);
  }

}
