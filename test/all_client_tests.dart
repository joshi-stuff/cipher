// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.test.all_client_tests;

import "package:unittest/html_enhanced_config.dart";

import "./all_tests.dart" as all_tests;
import "./api/registry_client_test.dart" as registry_client_test;

void main() {

  useHtmlEnhancedConfiguration();

  // registry
  registry_client_test.main();

  // base tests
  all_tests.main();

}