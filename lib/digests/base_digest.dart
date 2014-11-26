// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.digests.base_digest;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/algorithm/base_algorithm.dart";

/// Base implementation of [Digest] which provides shared methods.
abstract class BaseDigest extends BaseParameterizedNamedAlgorithm implements Digest {

  BaseDigest(String algorithmName, Map<Param, dynamic> params) : super(algorithmName, params);

  Uint8List process(Uint8List data) {
    update(data, 0, data.length);
    var out = new Uint8List(digestSize);
    var len = doFinal(out, 0);
    return out.sublist(0, len);
  }

}
