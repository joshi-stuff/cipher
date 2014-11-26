// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

part of cipher.api;

/// The interface that all algorithms conform to.
abstract class Algorithm {

}

/// The interface that all named algorithms conform to.
abstract class NamedAlgorithm extends Algorithm {

  /// Get this algorithm's standard name.
  String get algorithmName;

}

/// The interface that all parameterized algorithms conform to.
abstract class ParameterizedAlgorithm implements Algorithm {

  /// Get an unmodifiable view of this algorithm's configuration parameters.
  Map<Param, dynamic> get parameters;

}

/// The interface that all algorithms that can process data at one time conform to.
abstract class ProcessorAlgorithm implements Algorithm {

  /// Process a whole block of [data] at once, returning the result in a new byte array.
  Uint8List process(Uint8List data);

}

/// The interface that all algorithms that can be reset to their initial state conform to.
abstract class ResetableAlgorithm implements Algorithm {

  /// Reset the algorithm to its original state.
  void reset();

}

/// The interface that all parameterized named algorithms conform to.
abstract class ParameterizedNamedAlgorithm implements NamedAlgorithm, ParameterizedAlgorithm {

}
