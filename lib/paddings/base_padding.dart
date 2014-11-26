// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.paddings.base_padding;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/algorithm/base_algorithm.dart";

/// Base implementation of [Padding] which provides shared methods.
abstract class BasePadding extends BaseParameterizedNamedAlgorithm implements Padding {

  final bool forPadding;
  final int blockSize;

  BasePadding(String algorithmName, Map<Param, dynamic> params)
      : super(algorithmName, params),
        forPadding = params[Param.ForPadding],
        blockSize = params[Param.BlockSize];

  Uint8List process(Uint8List data) {
    if (forPadding) {
      final padSize = blockSize - (data.length % blockSize);
      final out = new Uint8List(data.length + padSize);
      out.setAll(0, data);
      addPadding(out, out.length - padSize);
      return out;
    } else {
      final padSize = countPadding(data);
      final out = new Uint8List(data.length - padSize);
      out.setRange(0, data.length - padSize, data);
      return out;
    }
  }

  void addPadding(Uint8List data, int padOffset);

  int countPadding(Uint8List data);

}
