#!/bin/bash
#
# This script can be called to setup the environment variables
# to support the sample code.
#
# Call this script using the DOT notation:
# . /.../setenv.sh
#
# Or, source it:
# source /.../setenv.sh
#

if [ "$0" = "$BASH_SOURCE" ]; then
	echo "You should run this script using 'source'"
	exit 1
fi

SCRIPTDIR="$( cd "$(dirname "$BASH_SOURCE")" ; pwd -P )"
PROJDIR="${SCRIPTDIR}/../.."

ASN1MODULESDIR="${PROJDIR}/../pyasn1-alt-modules"
if [ -d "${ASN1MODULESDIR}" ]; then
	if [[ -z "$PYTHONPATH" ]]; then
		export PYTHONPATH="${ASN1MODULESDIR}"
	else
		export PYTHONPATH="${ASN1MODULESDIR}:$PYTHONPATH"
	fi
else
	echo "Unable to find project for pyasn1-alt-modules"
	exit 1
fi
