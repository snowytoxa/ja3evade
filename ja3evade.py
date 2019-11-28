#!/usr/bin/env python
import ssl
import socket
from random import shuffle

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.ssl_ import create_urllib3_context



def get_ciphers():
    ssl_context = ssl.create_default_context()
    ciphers_list = [cs['name'] for cs in ssl_context.get_ciphers()]
    shuffle(ciphers_list)
    return ':'.join(ciphers_list)


class FakeAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=get_ciphers())
        kwargs['ssl_context'] = context
        return super(FakeAdapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=CIPHERS)
        kwargs['ssl_context'] = context
        return super(FakeAdapter, self).proxy_manager_for(*args, **kwargs)


def example_ssl_socket():
    context = ssl.create_default_context()
    context.set_ciphers(get_ciphers())
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sslSocket = context.wrap_socket(s, server_hostname='google.com')
    sslSocket.connect(('google.com', 443))
    sslSocket.close()


def example_requests_session():
    s = requests.Session()
    s.mount('https://google.com', FakeAdapter())
    r = s.get('https://google.com')


if __name__ == "__main__":
    example_ssl_socket()
    example_requests_session()
