import mitmproxy.http
from bs4 import BeautifulSoup
import json

SRC = "https://www.google.com"

TARGET_HOST = "tw.yahoo.com"
TARGET_URL = ""

class Insertor:
    def response(self, flow: mitmproxy.http.HTTPFlow) -> None:
        soup = BeautifulSoup(flow.response.get_text(), 'html.parser')

        if soup.head:
            script_soup = BeautifulSoup('<script></script>', 'html.parser')
            script_soup.find('script')['src'] = SRC

            soup.head.append(script_soup)
            flow.response.set_text(str(soup))
        else:
            pass
        
        return None