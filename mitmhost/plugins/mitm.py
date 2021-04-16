from mitmproxy.http import HTTPFlow as Flow
from mitmproxy.http import HTTPResponse as Response
from mitmproxy.http import HTTPRequest as Request
from mitmproxy.net.http.headers import Headers
from bs4 import BeautifulSoup
import json
import os
from datetime import datetime
from dateutil import parser
import time

class FakeUpdate(object):

    def __init__(self):
        self.entrypoints_url = "http://gist.url/entrypoint.js"
        self.info_profiler = "http://info_profiler.js"


class AttackHandler:
    """
    self.atkstart: The start time of whole simulated attack
    self.atkend: The end time of whole simulated attack
    """

    def __init__(self) -> None:
        ATK_HOME = os.environ['MITM_RESOURCE_DIR']

        # Sanitizing check if attack modules directory exists
        assert os.path.exists(ATK_HOME), f"ATK_HOME(Attack Module) directory not found in docker volume with {ATK_HOME}"
        
        self.proxies_mapping = {}
        self.landing_host_mapping = {}

        for case_dir in os.listdir(ATK_HOME):
            case_proxy_rule = os.path.join(
                ATK_HOME, 
                case_dir, 
                'proxy_rules', 
                'proxy_rules.json'
            )
            if not os.path.exists(case_proxy_rule):
                continue

            with open(case_proxy_rule) as fd:
                case_config = json.load(fd)

            assert type(case_config) == dict, f"Mal-formed proxy rules in case: {case_dir}"
            case_rule = case_config.get('simrules', {})

            #==================================== Load landing page config
            self.landing_host_mapping = \
                {
                    **self.landing_host_mapping,
                    **{case_rule.get('landing_host'): case_rule.get('landing_method')}
                }
            
            self.proxies_mapping = \
                {
                    **self.proxies_mapping,
                    **{k.get('url'):k for k in case_rule.get('objects')}
                }
            print(self.proxies_mapping)
        return None

    def http_connect(self, flow: Flow) -> None:
        print(
            f'''
            [INFO] http connection triggered with
                url: {flow.request.url},
                pretty_url: {flow.request.pretty_url},
                port: {flow.request.port},
                scheme: {flow.request.scheme},
                path: {flow.request.path},
                mathced_object: {self.proxies_mapping.get(flow.request.url, None)},
                headers: {flow.request.headers.items()}
            '''
        )
        https_url = "".join(
            [
                "http",
                "s" if "443" in flow.request.url.split(":") else "",
                "://",
                flow.request.url.split(":")[0]
            ]
        )
        if not any(
            map(
                lambda x: x.startswith(https_url),
                self.proxies_mapping.keys()
            )):
            return None
        
        flow.request.scheme = 'https'
        flow.request.port = 5000
        flow.request.host = 'localhost'

        print('[INFO] http connection change complete')
        return None

    def request(self, flow: Flow) -> None:
        #print(f'[INFO] Request url: {flow.request.url}')
        if flow.request.host == 'localhost' and flow.request.port == 5000:
            """
            print(
                f'''
                [Info] Local certificate triggered:
                    url: {flow.request.url},
                    path: {flow.request.path},
                    names: {list(map(lambda x: x.get('name', None), self.proxies_mapping.values()))}
                ''')
            """
            obj = list(filter(lambda x: x.get('name', None) == flow.request.path[1:], self.proxies_mapping.values()))
            assert len(obj) <= 1, f"[Error] Duplicated object found with path {flow.request.path} and objects are: {obj}"
            obj = obj[0] if obj else None
            pass
        else:
            #print(f'[Info] Local certificate not triggered and url is {flow.request.url}')
            obj = self.proxies_mapping.get(flow.request.url, None)

        if obj is None:
            #print(f'[INFO] obj is not found with url: {flow.request.url}')
            return None
        #print(f'[INFO] Request url: {flow.request.url}, and pretty_url is {flow.request.pretty_url}, and obj is: {obj}')
        assert type(obj) == dict, "[ERROR] Object config mal-form"
        flow.request.url = "".join(
            [
                "https",
                "://localhost", 
                ":",
                "5000",
                "/",
                obj.get('identifier', "err")
            ]
        )
        flow.request.headers['Host'] = 'localhost'
        print("[INFO] malicious request redirection detected")
        print(f"[INFO] malicious request header: {flow.request.headers.items()}")
        print(f"[INFO] malicious request url: {flow.request.url} at time: {time.time()}")
        return None
        
    
    def response(self, flow: Flow) -> None:
        print(
            f"""
            [INFO] Detect Response:
                From {flow.request.host} to {flow.client_conn.address}
                Time: {time.time()}
                User-Agent: {flow.request.headers['User-Agent']}
                """
            )
        trgt = self.landing_host_mapping.get(flow.request.host, None)
        if trgt is None:
            return None
        assert type(trgt) is dict,\
            f"[ERROR] Mal-formed infected page landing information with: {trgt}"
        
        if trgt.get('strict', False):
            tst_url = trgt.get('url', False)
            if tst_url:
                if not tst_url == flow.request.url:
                    return None
                else: pass
            else: pass

        ctype = flow.response.headers.get('Content-Type', "NULL")
        #print(f"[INFO] ctype is {ctype} with request headers: {flow.request.headers.items()} and timestamp: {time.time()}")
        if not ctype.split(";")[0] == 'text/html':
            return None
        
        soup = BeautifulSoup(flow.response.get_text(), 'html.parser')

        if not soup.head:
            return None
        
        script_soup = BeautifulSoup(trgt.get('node_str', '<script></script>'), 'html.parser')

        soup.body.append(script_soup)
        flow.response.set_text(str(soup))
        print("[INFO] Trigger modification")
        return None