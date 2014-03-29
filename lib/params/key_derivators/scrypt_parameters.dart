// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.params.key_derivators.scrypt_parameters;

import "dart:typed_data";
import "package:collection/equality.dart";

import "package:cipher/api.dart";

/**
 * [CipherParameters] for the scrypt password based key derivation function.
 */
class ScryptParameters implements CipherParameters {

  final int N;
  final int r;
  final int p;
  final int desiredKeyLength;
  final Uint8List salt;

  ScryptParameters( this.N, this.r, this.p, this.desiredKeyLength, this.salt );

  @override
  int get hashCode {
    return N.hashCode ^ r.hashCode ^ p.hashCode ^ desiredKeyLength.hashCode ^ new ListEquality().hash(salt);
  }

  @override
  bool operator ==(ScryptParameters other) {
    if(other is! ScryptParameters) return false;
    return N == other.N &&
        r == other.r &&
        p == other.p &&
        desiredKeyLength == other.desiredKeyLength &&
        new ListEquality().equals(salt, other.salt);
  }
}
