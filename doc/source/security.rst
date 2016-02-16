=================
Security in mlvpn
=================
Security is a very strong focus for the mlvpn project.

mlvpn tries it's best to protect your systems and your datas by using `privilege separation`_,
`strong cryptography`_, and continuous integration.

.. _`privilege_separation`: http://en.wikipedia.org/wiki/Privilege_separation
.. _`strong cryptography`: http://doc.libsodium.org/

Privilege separation
====================
mlvpn needs to access the kernel in order to create a tunnel device, and in order
to configure the device. (needs root)

In order to limit the scope of privileges, mlvpn spawns a small process, called the
[priv] process, then another one.

The priv process only performs the tasks where it needs privileges:
  * tunnel interface creation
  * tunnel interface configuration
  * open the mlvpn configuration file
  * name resolution (requires to be out of the chroot)

The other process is run as an unprivileged user (usually _mlvpn or mlvpn),
in a chroot. It handles all the hard work exposed to the outside world.

This is the same technique used in `OpenSSH <http://www.openssh.org>`_.

Cryptography
============
mlvpn uses `libsodium <http://doc.libsodium.org>`_ for all the cryptographic needs.

In particular, mlvpn uses `secret-key authenticated encryption <http://doc.libsodium.org/secret-key_cryptography/authenticated_encryption.html>`_.

Cryptography is used for two purposes:
  * Authentication
  * Data protection

Authentication
--------------
mlvpn just uses a very simple protocol in order to make sure it communicates only
if the two sides share the same secret key.

The secret key is stored as plain text in the mlvpn configuration file.

This configuration file must be owned by root, and chmoded to 0600 to prevent
any other user from reading / writing to it.

Every control packet sent by mlvpn is encrypted and authenticated by both sides.

Authentication is done using Poly1305 MAC.

Encryption
----------
Data packets can be encrypted/authenticated as well, but this can be disabled by using the
*cleartext_data* configuration flag.

This can be usefull if your on a budget, with lack of CPU.

If your data are going to the internet anyway, there is no point in trying to cipher them
another time using mlvpn. (encrypting an ssh or https connections does not give you much benefit)

Encryption is done using the XSalsa20 algorithm.
