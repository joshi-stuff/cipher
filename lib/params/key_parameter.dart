// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com  
// Use of this source code is governed by a LGPL v3 license. 
// See the LICENSE file for more information.

library cipher.params.key_parameter;

import "dart:typed_data";

import "package:collection/equality.dart";
import "package:cipher/api.dart";

/// [CipherParameters] consisting of just a key of arbitrary length.
class KeyParameter extends CipherParameters {
  
  final Uint8List key;
  
  KeyParameter(this.key);

  @override
  int get hashCode {
    return new ListEquality().hash(key);
  }

  @override
  bool operator ==(KeyParameter other) {
    if(other is! KeyParameter) return false;
    return new ListEquality().equals(key, other.key);
  }
  
}
