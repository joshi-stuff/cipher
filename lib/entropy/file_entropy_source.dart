// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.entropy.file_entropy_source;

import "dart:async";
import "dart:typed_data";
import "dart:io";

import "package:cipher/api.dart";

class FileEntropySource implements EntropySource {

  final _filePath;

  String get sourceName => "file://${_filePath}";

  FileEntropySource(this._filePath);

  void seed( CipherParameters params ) {
  }

  Future<Uint8List> getBytes( int count ) {
    var completer = new Completer<Uint8List>();

    var data = new Uint8List(count);
    var offset = 0;
    new File(_filePath).openRead(0, count).listen(
      (bytes) {
        data.setRange(offset, offset+bytes.length, bytes);
        offset += bytes.length;
      },
      onError: (error, stackTrace) {
        completer.completeError(error, stackTrace);
      },
      onDone: () {
        completer.complete(data);
      },
      cancelOnError: true
    );

    return completer.future;
  }

}