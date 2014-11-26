// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.registry;

/// A factory of registered objects.
typedef dynamic Factory(String name, Map params);

/// A registry holds the map of factories indexed by algorithm names.
class Registry<T> {

  final _staticFactories = new Map<String, Factory>();
  final _dynamicFactories = new List<Factory>();

  /// Shorthand for [registerStaticFactory]
  operator []=(String name, Factory factory) => registerStaticFactory(name, factory);

  /// Register an algorithm by its name.
  void registerStaticFactory(String name, Factory factory) {
    _staticFactories[name] = factory;
  }


  /// Register an algorithm factory method which can translate a variable algorithm name into an
  /// implementation.
  void registerDynamicFactory(Factory factory) {
    _dynamicFactories.add(factory);
  }

  /// Create an algorithm given its name
  T create(String name, Map params) {
    var factory = _staticFactories[name];
    if (factory != null) {
      return factory(name, params);
    } else {
      for (factory in _dynamicFactories) {
        var algorithm = factory(name, params);
        if (algorithm != null) {
          return algorithm;
        }
      }
    }
    throw new UnsupportedError("No factory for objects with name '${name}' registered");
  }

}
