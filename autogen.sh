#!/bin/sh -e

AUTORECONF=${AUTORECONF:-autoreconf}
ACLOCAL=${ACLOCAL:-aclocal}
AUTOCONF=${AUTOCONF:-autoconf}
AUTOMAKE=${AUTOMAKE:-automake}

# Check we have all tools installed
check_command() {
    command -v "${1}" > /dev/null 2>&1 || {
        >&2 echo "autogen.sh: could not find \`$1'. \`$1' is required to run autogen.sh."
        exit 1
    }
}
check_command "$AUTORECONF"
check_command "$ACLOCAL"
check_command "$AUTOCONF"
check_command "$AUTOMAKE"

exec autoreconf -fi
