#!/bin/sh

nsdebug=""
fulldomain=$1
txtvalue=$2

NSUPDATE_SERVER=${NSUPDATE_SERVER:-localhost}
NSUPDATE_SERVER_PORT=${NSUPDATE_SERVER_PORT:-5053}
NSUPDATE_KEYFILE=${NSUPDATE_KEYFILE:-"./tsigfile"}
usage()
{
        echo "$0: fulldomain txtvalue"
        echo ""
        echo "Accepted environment variables:"
        echo ""
        echo NSUPDATE_KEYFILE
        echo NSUPDATE_SERVER
        echo NSUPDATE_SERVER_PORT
        echo NSUPDATE_ZONE
        echo ""
        exit 1
}

err()
{
        local _e=$1
        shift

        echo "Error" $*
        exit ${_e}
}

[ -z "${fulldomain}" ] && usage
[ -z "${txtvalue}" ] && usage


if [ -z "${NSUPDATE_ZONE}" ]; then
    nsupdate -k "${NSUPDATE_KEYFILE}" $nsdebug <<EOF
server ${NSUPDATE_SERVER}  ${NSUPDATE_SERVER_PORT}
update add ${fulldomain}. 60 in txt "${txtvalue}"
send
EOF
else
    nsupdate -k "${NSUPDATE_KEYFILE}" $nsdebug <<EOF
server ${NSUPDATE_SERVER}  ${NSUPDATE_SERVER_PORT}
zone ${NSUPDATE_ZONE}.
update add ${fulldomain}. 60 in txt "${txtvalue}"
send
EOF
fi
