"""
HTTP OAuth downloader middleware

See documentation in docs/topics/downloader-middleware.rst
"""
from oauthlib.oauth1 import Client as Oauth1Client
from oauthlib.oauth2 import InsecureTransportError
from oauthlib.oauth2 import WebApplicationClient as Oauth2Client

from scrapy import signals


class HttpOAuth1Middleware(object):
    """Set Oauth 1.0 RFC 5849 HTTP Authorization header"""

    @classmethod
    def from_crawler(cls, crawler):
        o = cls()
        crawler.signals.connect(o.spider_opened, signal=signals.spider_opened)
        return o

    def spider_opened(self, spider):
        client = getattr(spider, 'oauth_client', None)
        if client:
            self.auth = client
        else:
            client_key = getattr(spider, 'oauth_client_key', None)
            client_secret = getattr(spider, 'oauth_client_secret', None)
            resource_owner_key = getattr(spider, 'oauth_resource_owner_key', None)
            resource_owner_secret = getattr(spider, 'oauth_resource_owner_secret', None)
            if all((client_key, client_secret, resource_owner_key, resource_owner_secret)):
                self.auth = Oauth1Client(
                    client_key,
                    client_secret=client_secret,
                    resource_owner_key=resource_owner_key,
                    resource_owner_secret=resource_owner_key)

    def process_request(self, request, spider):
        auth = getattr(self, 'auth', None)
        if auth and 'Authorization' not in request.headers:
            headers = self.auth.sign(request.url)
            request.replace(headers=headers)
            # request.headers['Authorization'] = oauth_header['Authorization']


class HttpOAuth2Middleware(object):
    """Set Oauth 2.0 RFC 6749 HTTP Authorization header"""

    @classmethod
    def from_crawler(cls, crawler):
        o = cls()
        crawler.signals.connect(o.spider_opened, signal=signals.spider_opened)
        return o

    def spider_opened(self, spider):
        client = getattr(spider, 'oauth_client', None)
        if client:
            self.auth = client
        else:
            client_id = getattr(spider, 'oauth_client_id', None)
            token = getattr(spider, 'oauth_token', None)
            if all((client_id, token)):
                self.auth = Oauth2Client(client_id, token=token)

    def _is_secure_transport(uri):
        return uri.lower().startswith('https://')

    def process_request(self, request, spider):
        auth = getattr(self, 'auth', None)
        if auth and 'Authorization' not in request.headers:
            if not self._is_secure_transport(request.url):
                raise InsecureTransportError()
            url, headers, body = self.auth.add_token(
                request.url,
                http_method=request.method,
                body=request.body,
                headers=request.headers)
            request.replace(
                url=url,
                headers=headers
                body=body)
