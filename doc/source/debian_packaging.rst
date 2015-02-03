==================================
Building debian packages for mlvpn
==================================

Requirements
============

.. code-block:: sh

    sudo apt-get install pbuilder cowbuilder git-buildpackage


Prepare build environments
==========================

Configure pbuilder
------------------

.pbuilderrc:

.. code-block:: sh

    # Template loosely taken from http://www.kirya.net/articles/build-i386-packages-on-amd64/
    # do not specify variables when running cowbuilder --create or --update
    if [ -f debian/changelog ]; then
            [ -z "$ARCH" ] && ARCH=$(dpkg --print-architecture)
            [ -z "$DIST" ] && DIST=$(dpkg-parsechangelog | sed -n 's/^Distribution: //p')
    fi
    PDEBUILD_PBUILDER="cowbuilder --build --basepath /var/cache/pbuilder/base-${DIST}_${ARCH}.cow"
    DEBBUILDOPTS="-d ${OPTS}"
    ARCHITECTURE=${ARCH}
    BUILDRESULT=~/build-area
    MIRRORSITE=http://ftp.fr.debian.org/debian
    EXTRAPACKAGES="$EXTRAPACKAGES lintian apt-utils"
    AUTO_DEBSIGN=yes
    HOOKDIR=${HOME}/.pbuilder/hooks/
    PKGNAME_LOGFILE_EXTENTION="_${ARCH}.build"
    # Allow a local repository for external backported dependencies.
    OTHERMIRROR="deb [trusted=yes] file://${HOME}/build-area ./"
    BINDMOUNTS="${HOME}/build-area"

Generate base images for pbuilder
---------------------------------

.. code-block:: sh

    for arch in i386 amd64; do
        sudo cowbuilder --config ~/.pbuilderrc --create --distribution wheezy --architecture $arch --basepath /var/cache/pbuilder/base-wheezy_$arch.cow
        sudo cowbuilder --config ~/.pbuilderrc --update --distribution wheezy --architecture $arch --basepath /var/cache/pbuilder/base-wheezy_$arch.cow
    done


Build packages
==============

libsodium13 (for wheezy)
------------------------

.. code-block:: sh

    dget -x http://ftp.fr.debian.org/debian/pool/main/libs/libsodium/libsodium_1.0.0-1.dsc
    cd libsodium_1.0.0
    for dist in wheezy; do
        for arch in amd64 i386; do
            DIST=$dist ARCH=$arch pdebuild --debbuildopts -b
        done
    done

mlvpn
-----

.. code-block:: sh

    git clone git@github.com:zehome/MLVPN.git mlvpn
    cd mlvpn
    git checkout debian-unstable
    for dist in wheezy; do
        for arch in amd64 i386; do
            DIST=$dist ARCH=$arch git-buildpackage --git-builder="pdebuild --debbuildopts -b"
        done
    done
