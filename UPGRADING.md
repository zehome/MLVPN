Upgrading version 1.X to version 2.X
====================================

dependencies
------------
mlvpn requires libsodium and libev to run.

```sh
apt-get install libsodium-dev libev-dev
```

mlvpn.conf
----------

  * **protocol** is not supported anymore. Only UDP is supported.
  * **loglevel** is not supported anymore.
  * **password** is a new **mandatory* setting used for auth and cipher.
  * **bandwidth_download** must be replaced by bandwidth_upload on the server
    side and removed client side.
  * **cleartext_data** is a new setting to allow better performance on very
    modest machines when running HIGH bandwidth uplinks.
  * **fallback_only** is a new setting (per tunnel) allowing the use of a
    "backup" link only enabled with all other normal links are down.



Check the permissions of the configuration files. It **MUST** be 0600.
