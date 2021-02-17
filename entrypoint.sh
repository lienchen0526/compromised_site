#!/bin/sh
pip3 install -r /home/mitmproxy/plugins/requirements.txt
chown -R mitmproxy:mitmproxy /home/mitmproxy/.mitmproxy
su-exec mitmproxy mitmdump\
    -s /home/mitmproxy/plugins/src/addons.py
    --set block_global=false