// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.params.key_generators.ec_key_generator_parameters;

import "package:cipher/api.dart";
import "package:cipher/api/ecc.dart";
import "package:cipher/params/key_generators/key_generator_parameters.dart";

/// Abstract [CipherParameters] to init an ECC key generator.
class ECKeyGeneratorParameters extends KeyGeneratorParameters {

  ECDomainParameters _domainParameters;

  ECKeyGeneratorParameters(ECDomainParameters domainParameters)
    : super(domainParameters.n.bitLength()) {
    _domainParameters = domainParameters;
  }

  ECDomainParameters get domainParameters => _domainParameters;

}
