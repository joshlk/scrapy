"""
HTTP OAuth downloader middleware

See documentation in docs/topics/downloader-middleware.rst
"""
from collections import deque
from time import time, sleep
from oauthlib.oauth1 import Client as Oauth1Client
from oauthlib.oauth2 import InsecureTransportError
from oauthlib.oauth2 import WebApplicationClient as Oauth2Client
from scrapy.exceptions import DontCloseSpider, NotConfigured, IgnoreRequest

from scrapy import signals


class HttpOAuth1Middleware(object):
    """Oauth 1.0 RFC 5849"""

    @classmethod
    def from_crawler(cls, crawler):
        o = cls()
        crawler.signals.connect(o.spider_opened, signal=signals.spider_opened)
        crawler.signals.connect(o.spider_idle, signal=signals.spider_idle)
        return o

    def spider_opened(self, spider):
        # 'tokens' is a list of dictionaries which contain:
        # oauth_client_key, oauth_client_secret, oauth_resource_owner_key, oauth_resource_owner_secret
        tokens = getattr(spider, 'oauth_token_list', None)
        self.check_response  = getattr(spider, 'oauth_check_response_func', self.default_check_response)
        self.REQUEST_WINDOW_SIZE_MINS = getattr(spider, 'oauth_request_windows_size_mins', 0)

        if tokens is None:
            raise NotConfigured

        # Make dead and live token deque
        self.tokens_live = deque()
        # All tokens start off in dead deque. Contains tuples: (token, time_died)
        self.tokens_dead = deque(zip(tokens, [float('-inf')] * len(tokens)))

        self.requests_on_hold = []

    def process_request(self, request, spider):
        # Obtain token
        token, requests_done = self._obtain_token(spider)

        if token is None:
            # Add to requests on hold list and do request later
            self.requests_on_hold.append(request)
            raise IgnoreRequest

        auth = Oauth1Client(
            client_key=token['client_key'],
            client_secret=token['client_secret'],
            resource_owner_key=token['resource_owner_key'],
            resource_owner_secret=token['resource_owner_secret'])

        uri, headers, body = auth.sign(request.url)
        #request = request.replace(headers=headers)
        request.headers['Authorization'] = [headers['Authorization']]

        request.meta['oauth'] = True
        request.meta['token'] = token

    def process_response(self, request, response, spider):
        ''' Change token if required and retry if necessary '''

        oauth_used = request.meta.get('oauth', False)

        if oauth_used:
            token_dead, retry_request = self.check_response(response)

            # Always recycle the token and put it somewhere
            token = request.meta['token']
            if token_dead:
                self.tokens_dead.append((token, time()))
            else:
                requests_succeed = request.meta['token_requests_succeed']
                requests_succeed += 1
                self.tokens_live.append((token, requests_succeed))

            if retry_request == True:
                # Reschedule request but remove the token
                del request.meta['token']
                del request.meta['oauth']
                return request
            else:
                # Request success
                return response

    def spider_idle(self, spider):

        if len(self.requests_on_hold) != 0:
            # Use live tokens if some remain
            if len(self.tokens_live) == 0:

                # How much time left until we can reuse the dead tokens
                time_left = self._dead_token_time_left()

                # If still need to wait then sleep
                if time_left > 0:
                    sleep(time_left)        # TODO: need to change

            # Reschedule requests with the spider
            for r in self.requests_on_hold:
                spider.crawler.engine.crawl(r, spider)

            self.requests_on_hold = []  # Clear request on hold
            raise DontCloseSpider()  # Stop the spider from closing

    def default_check_response(self, response):
        # By default just cycle through all the tokens
        # return: token_dead, retry_request
        return True, False

    def _dead_token_time_left(self):
        '''
        Returns the number of seconds left until the first dead tokens can be used again.
        If there are no dead tokens return infinity
        '''
        if len(self.tokens_dead) > 0:
            cred, time_expired = self.tokens_dead[0]  # Peek at the beginning of the queue
            time_left = self.REQUEST_WINDOW_SIZE_MINS * 60 - (time() - time_expired)
            time_left = time_left if time_left > 0 else 0  # Make 0 if time_left is -ve
            return time_left
        else:
            return float('inf')

    def _obtain_token(self, spider):
        ''' Obtain a token from the live or dead deque. Returns None if no current tokens '''

        # Check to see if there there any tokens available to use
        if len(self.tokens_live) == 0 and self._dead_token_time_left() > 0:
            return None, None

        if len(self.tokens_live) > 0:
            token, requests_succeed = self.tokens_live.popleft()
        else:
            # Obtain from dead queue
            token, _ = self.tokens_dead.popleft()
            requests_done = 0

        return token, requests_done





class HttpOAuth2Middleware(object):
    """Oauth 2.0 RFC 6749"""

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

    def _is_secure_transport(self, uri):
        return uri.lower().startswith('https://')

    def process_request(self, request, spider):
        auth = getattr(self, 'auth', None)
        oauth_used = request.meta.get('oauth', False)
        if auth and not oauth_used:
            if not self._is_secure_transport(request.url):
                raise InsecureTransportError()

            # Generate HTTP header
            url, headers, body = self.auth.add_token(
                request.url,
                http_method=request.method,
                body=request.body,
                headers=request.headers)

            # Add token header to request
            request = request.replace(
                url=url,
                headers=headers,
                body=body)

            request.meta['oauth'] = True
            return request
