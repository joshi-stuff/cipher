// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.block.base_algorithm;

import "dart:collection";

import "package:cipher/api.dart";


/// Base implementation of [Algorithm] which provides shared methods.
abstract class BaseAlgorithm implements Algorithm {

}

/// Base implementation of [NamedAlgorithm] which provides shared methods.
abstract class BaseNamedAlgorithm extends BaseAlgorithm implements NamedAlgorithm {

  final String algorithmName;

  BaseNamedAlgorithm(this.algorithmName);

}

/// Base implementation of [ParameterizedNamedAlgorithm] which provides shared methods.
abstract class BaseParameterizedNamedAlgorithm extends BaseNamedAlgorithm implements
    ParameterizedNamedAlgorithm {

  final UnmodifiableMapView<Param, dynamic> parameters;

  BaseParameterizedNamedAlgorithm(String algorithmName, Map<Param, dynamic> params)
      : super(algorithmName),
        parameters = _makeUnmodifiableMapView(params);

  static UnmodifiableMapView<Param, dynamic> _makeUnmodifiableMapView(Map<Param, dynamic> params) {
    var unmodifiableParams = <Param, dynamic>{};

    params.forEach((param, value) {
      if (value is Map) {
        unmodifiableParams[param] = _makeUnmodifiableMapView(value);
      } else if (value is List) {
        unmodifiableParams[param] = _makeUnmodifiableListView(value);
      } else {
        unmodifiableParams[param] = value;
      }
    });

    return new UnmodifiableMapView<Param, dynamic>(unmodifiableParams);
  }

  static UnmodifiableListView _makeUnmodifiableListView(List values) {
    var unmodifiableValues = new List(values.length);

    for (int i = 0; i < values.length; i++) {
      var value = values[i];

      if (value is Map) {
        unmodifiableValues[i] = _makeUnmodifiableMapView(value);
      } else if (value is List) {
        unmodifiableValues[i] = _makeUnmodifiableListView(value);
      } else {
        unmodifiableValues[i] = value;
      }
    }

    return new UnmodifiableListView(unmodifiableValues);
  }

}
