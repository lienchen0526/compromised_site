from urllib import request
import ssl
import os
import mitm

c2_backend = os.environ['HTTP_CONTAINER_DOMAIN']
c2_port = os.environ['HTTP_CONTAINER_PORT']

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

try:
    ready = request.urlopen(
        url = "".join(["https://", "localhost", ":", c2_port]),
        context = ctx
    ).reason == 'OK'
except:
    ready = False
while not ready:
    try:
        ready = request.urlopen(
            url = "".join(["https://", "localhost", ":", c2_port]),
            context = ctx
        ).reason == 'OK'
    except:
        ready = False
    
addons = [
    mitm.AttackHandler()
]