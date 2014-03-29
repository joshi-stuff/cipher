// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com  
// Use of this source code is governed by a LGPL v3 license. 
// See the LICENSE file for more information.

library cipher.params.parameters_with_iv;

import "dart:typed_data";

import "package:collection/equality.dart";
import "package:cipher/api.dart";

/**
 * [CipherParameters] consisting of an underlying [CipherParameters] (of type [UnderlyingParameters]) and an initialization 
 * vector of arbitrary length.
 */
class ParametersWithIV<UnderlyingParameters extends CipherParameters> implements CipherParameters {
  
    final Uint8List iv;
    final UnderlyingParameters parameters;

    ParametersWithIV( this.parameters, this.iv );

    @override
    int get hashCode {
      return parameters.hashCode ^ new ListEquality().hash(iv);
    }

    @override
    bool operator ==(ParametersWithIV other) {
      if(other is! ParametersWithIV) return false;
      return parameters == other.parameters &&
      new ListEquality().equals(iv, other.iv);
    }

}
