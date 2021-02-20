from flask import Flask, request, send_from_directory
from functools import reduce
import os, json

app = Flask(__name__)

GREETING = """
<h1>Hello, Welcome to Simulated C&C server</h1>
"""

NOT_FOUND_ERR = """
Resource not found.
"""

attack_dist_rules = {}

attack_cases = os.listdir(os.environ['HTTP_RESOURCE_DIR'])
for case in attack_cases:
    with open(os.path.join(os.environ['HTTP_RESOURCE_DIR'], case, 'rule.json')) as fd:
        attack_dist_rules[case] = json.load(fd)
        assert type(attack_dist_rules[case]) == dict,\
            f"""Wrong <rule.json> format with {type(attack_dist_rules[case])}"""

app.attack_dist_rules =  attack_dist_rules       

@app.route('/')
def c2_home() -> str:
    return GREETING

@app.route('/', defaults={'rstring': ''})
@app.route('/<path:rstring>')
def gather_resource(rstring = None):
    """
    The format of rstring can be:
    <testnumber>/<resourceid>
    """
    print(rstring)
    return None