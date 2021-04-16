#!/bin/sh
pip3 install -r ${MITMHOME}/plugins/requirements.txt
chown -R mitmproxy:mitmproxy ${MITMHOME}/.mitmproxy
chown -R mitmproxy:mitmproxy ${MITMHOME}/logs
su-exec mitmproxy mitmdump\
    -s ${MITMHOME}/plugins/addons.py\
    --set block_global=false\
    --set ssl_insecure=true