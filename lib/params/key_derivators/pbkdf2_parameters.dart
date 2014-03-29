// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.params.key_derivators.pbkdf2_parameters;

import "dart:typed_data";
import "package:collection/equality.dart";

import "package:cipher/api.dart";

/// [CipherParameters] used by PBKDF2.
class Pbkdf2Parameters extends CipherParameters {

  final Uint8List salt;
  final int iterationCount;
  final int desiredKeyLength;

  Pbkdf2Parameters(this.salt, this.iterationCount, this.desiredKeyLength);

  @override
  int get hashCode {
    return iterationCount.hashCode ^ desiredKeyLength.hashCode ^ new ListEquality().hash(salt);
  }

  @override
  bool operator ==(Pbkdf2Parameters other) {
    if(other is! Pbkdf2Parameters) return false;
    return iterationCount == other.iterationCount &&
    desiredKeyLength == other.desiredKeyLength &&
    new ListEquality().equals(salt, other.salt);
  }

}
