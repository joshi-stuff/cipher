// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

part of cipher.api;

/// The interface that a message digest conforms to.
abstract class Digest implements ParameterizedAlgorithm, ResetableAlgorithm, ProcessorAlgorithm {

  /// The [Registry] for [Digest] algorithms
  static final registry = new Registry<Digest>();

  /// Create the digest specified by the standard [algorithmName].
  factory Digest(String algorithmName, [Map<Param, dynamic> params = const {}]) =>
      registry.create(algorithmName, params);

  /// Get this digest's output size.
  int get digestSize;

  /// Add one byte of data to the digested input.
  void updateByte(int inp);

  /**
   * Add [len] bytes of data contained in [inp], starting at position [inpOff] to the digested
   * input.
   */
  void update(Uint8List inp, int inpOff, int len);

  /**
   * Store the digest of previously given data in buffer [out] starting at offset [outOff]. This
   * method returns the size of the digest.
   */
  int doFinal(Uint8List out, int outOff);

}

/// The interface that a padding conforms to.
abstract class Padding implements ParameterizedAlgorithm, ProcessorAlgorithm {

  /// The [Registry] for [Padding] algorithms
  static final registry = new Registry<Padding>();

  /// Create the digest specified by the standard [algorithmName].
  factory Padding(String algorithmName, Map<Param, dynamic> params) =>
      registry.create(algorithmName, params);

  /*
  int addPadding(Uint8List data, int offset);

  /// Get the number of pad bytes present in the block.
  int padCount(Uint8List data);
  */
}
