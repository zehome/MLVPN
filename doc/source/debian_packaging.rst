==================================
Building debian packages for mlvpn
==================================

Requirements
============

.. code-block:: sh

    sudo apt-get install pbuilder cowbuilder git-buildpackage


Prepare build environments
==========================

.. code-block:: sh

    sudo cowbuilder --create --distribution wheezy --architecture i386 --basepath /var/cache/pbuilder/base-wheezy_i386.cow
    sudo cowbuilder --create --distribution wheezy --architecture amd64 --basepath /var/cache/pbuilder/base-wheezy_amd64.cow

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
    EXTRAPACKAGES="$EXTRAPACKAGES lintian"
    AUTO_DEBSIGN=yes
    HOOKDIR=${HOME}/.pbuilder/hooks/
    PKGNAME_LOGFILE_EXTENTION="_${ARCH}.build"


Build packages
==============

.. code-block:: sh

    git clone git@github.com:zehome/MLVPN.git mlvpn
    cd mlvpn
    git checkout debian-unstable
    DIST=wheezy ARCH=i386 git-buildpackage --git-builder="pdebuild --debbuildopts -b"
    DIST=wheezy ARCH=amd64 git-buildpackage --git-builder="pdebuild --debbuildopts -b"

