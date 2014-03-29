// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com  
// Use of this source code is governed by a LGPL v3 license. 
// See the LICENSE file for more information.

library cipher.params.parameters_with_random;

import "package:cipher/api.dart";

class ParametersWithRandom<UnderlyingParameters extends CipherParameters> implements CipherParameters {
  
  final UnderlyingParameters parameters;
  final SecureRandom random;

  ParametersWithRandom(this.parameters,this.random);

  //TODO hashCode and equals currently only check the runtimeType of the SecureRandom
  //      is this enough?

  /**
   * Only the [runtimeType] of [random] is taken into account.
   */
  @override
  int get hashCode {
    return parameters.hashCode ^ random.runtimeType.hashCode;
  }

  /**
   * Only the [runtimeType] of [random] is taken into account.
   */
  @override
  bool operator ==(ParametersWithRandom other) {
    if(other is! ParametersWithRandom) return false;
    return parameters == other.parameters && random.runtimeType == other.random.runtimeType;
  }

}
