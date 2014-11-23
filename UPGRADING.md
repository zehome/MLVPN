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
  * **loglevel** can take value 0, 1 or 2. See documentation for details.
  * **password** is a new **mandatory* setting used for auth and cipher.
  * **bandwidth_download** must be replaced by bandwidth_upload on the server
    side and removed client side.


