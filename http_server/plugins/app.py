#!/usr/local/bin/python
from flask import Flask, request, send_from_directory, jsonify, Response
from functools import reduce
from typing import Union
import os, json
import io
from OpenSSL import SSL

app = Flask(__name__)

GREETING = """
<h1>Hello, Welcome to Simulated C&C server</h1>
"""

NOT_FOUND_ERR = """
Resource not found.
"""

attack_ids = {}
attack_dist_rules = {}

attack_cases = os.listdir(os.environ['HTTP_RESOURCE_DIR'])
for case in attack_cases:
    with open(os.path.join(os.environ['HTTP_RESOURCE_DIR'], case, 'rule.json')) as fd:
        case_info = json.load(fd)
    
    assert type(case_info) == dict,\
        f"""Wrong <rule.json> format with {type(case_info)}"""

    attack_ids = {**attack_ids, **case_info.get("identifier", {})}
    attack_dist_rules = {**attack_dist_rules, **case_info.get("resource_distribution_rules", {})}

app.config.update(
    ATTACK_DIST_RULES = attack_dist_rules
)
app.config.update(
    ATTACK_IDS = attack_ids
)

@app.route('/')
def c2_home() -> str:
    return GREETING

@app.route('/', defaults={'rstring': ''})
@app.route('/<path:rstring>', methods = ['POST', 'GET'])
def gather_resource(rstring = None):
    """
    The format of rstring can be:
    <rstring> is resource identifier which is global unique.
    """

    if not (dist := app.config['ATTACK_IDS'].get(rstring, False)):
        app.logger.warning(f"[WARN] Queried Resource does not found with identifier: {rstring} in {app.config['ATTACK_IDS']}")
        app.logger.warning(f"[WARN] from above: config is: {app.config['ATTACK_IDS']}")
        return NOT_FOUND_ERR
    
    assert type(dist) == str,\
        f"""Type of distribution <dist> must be str, however, {type(dist)} is detected"""
    
    if not (detail := app.config['ATTACK_DIST_RULES'].get(dist, False)):
        app.logger.warning(f"[WARN] Attack resource distribution chain error with defined identifier: {rstring} and mapped dist: {dist} but no any match detail distribution rules in server")
        return NOT_FOUND_ERR
    
    assert type(detail) == dict,\
        f"""Type of mapping of <dist> must be dict, however, {type(detail)} is detected"""
    
    case_home = os.path.join(os.environ['HTTP_RESOURCE_DIR'], detail.get("attack_origin", None), "src")

    if not os.path.exists(rsc_dir := os.path.join(case_home, dist)):
        app.logger.warning(f"[WARN] Real attack resource path does not exist. Attack resource alias: {dist}, expected directory: {rsc_dir}")
        app.logger.warning(f"------ current search path is {rsc_dir}")
        return NOT_FOUND_ERR

    def generate(fd: Union[io.BufferedReader, str], chunk_size: int = 2**20):
        if type(fd) == str:
            assert os.path.exists(fd), f"[WARN] file path does not exist in path {fd}"
        with open(fd, 'rb') as fd:
            while _cont := fd.read(chunk_size):
                yield _cont
    
    return Response(
        response = generate(
            fd = rsc_dir,
            chunk_size = detail.get('chunk_size', 2**20)
        ),
        status = 200,
        headers = detail.get('creply_headers', None),
        mimetype = detail.get('Content-Type', None)
    )

if __name__ == '__main__':
    http_home = os.environ.get('HTTPHOME')
    cert_dir = os.listdir(os.path.join(http_home, 'certs'))

    private_key_path = os.path.join(
        http_home,
        'certs',
        'private.key'
    )
    certificate_path = os.path.join(
        http_home,
        'certs',
        'c2.crt'
    )
    if not (os.path.exists(private_key_path) and os.path.exists(certificate_path)):
        from certmanage import cert_gen
        cert_gen(
            KEY_FILE = private_key_path,
            CERT_FILE = certificate_path
        )
    else:
        pass

    app.run(
        host = "0.0.0.0",
        port = os.environ.get('HTTP_CONTAINER_PORT', 5000),
        threaded = True,
        ssl_context = (
            certificate_path,
            private_key_path
        )
    )
