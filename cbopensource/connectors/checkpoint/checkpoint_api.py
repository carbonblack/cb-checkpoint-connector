import requests
import logging
import json
import traceback

logger = logging.getLogger(__name__)

from threading import Lock
from datetime import datetime, timedelta
import time
import logging
from requests.adapters import HTTPAdapter
from requests import Session
import sys

log = logging.getLogger(__name__)


class APIQuotaExceededError(Exception):
    pass


class APISession(Session):
    def __init__(self, request_quota=None, throttle_per_minute=None, api_key=None):
        super(APISession, self).__init__()
        self.request_quota = request_quota
        self.throttle_per_minute = throttle_per_minute

        self.api_key = api_key
        self.current_api_key_index = 0
        self.current_api_key_index_lock = Lock()

        self.request_lock = Lock()

        self.total_request_count = 0
        self.total_reply_count = 0

        # throttling
        self.current_minute = datetime.now()
        self.requests_current_minute = 0

        # quota
        self.current_quota_usage = 0

        self.wait_until = None

    # def apply_api_key(self, request):
    #     if len(self.api_keys) == 0:
    #         log.fatal("No valid API keys remaining, exiting")
    #         sys.exit(2)
    #
    #     if request.method == "GET":
    #         return request
    #     elif type(request.data) == dict:
    #         request.data['apikey'] = self.api_keys[self.current_api_key_index]
    #
    #     return request

    def prepare_request(self, request):
        #request = self.apply_api_key(request)
        return super(APISession, self).prepare_request(request)

    def send(self, request, **kwargs):
        if self.request_quota:
            self.current_quota_usage += 1
            if self.current_quota_usage > self.request_quota:
                self.set_wait_time()

        if self.wait_until:
            sleep_time = (self.wait_until - datetime.now()).total_seconds()
            if sleep_time > 0:
                time.sleep(sleep_time)
            self.wait_until = None

        # next, apply throttling
        if self.throttle_per_minute:
            now = datetime.now()
            if now - self.current_minute > timedelta(minutes=1):
                self.current_minute = now
                self.requests_current_minute = 0
            else:
                self.requests_current_minute += 1

            if self.requests_current_minute > self.throttle_per_minute:
                log.info("Too many API requests in the past 60 seconds (limit is {0}). Waiting one minute..."
                         .format(self.throttle_per_minute))
                time.sleep(60)
                self.requests_current_minute = 0
                self.current_minute = datetime.now()

        return super(APISession, self).send(request, **kwargs)

    def set_wait_time(self):
        if self.wait_until:
            return

        # default quota strategy: wait an hour before trying again
        next_time = datetime.now()
        self.wait_until = next_time.replace(hour=(next_time.hour + 1))

        log.info("Reached API quota limit for all API keys. Waiting until {0} to try again.".format(self.wait_until))
        self.current_quota_usage = 0

    def request(self, *args, **kwargs):
        with self.request_lock:
            successful = False

            while not successful:
                self.total_request_count += 1
                response = super(APISession, self).request(*args, **kwargs)
                self.total_reply_count += 1
                return response


def checkpoint_submit_binary():
    pass


def checkpoint_query(url, api_key, md5):
    response = None
    try:
        response = requests.post(
            url=url,
            headers={
                "Content-Type": "application/json",
                "Authorization": api_key,
            },
            data=json.dumps({
                "request": [
                    {
                        "md5": md5,
                        "features": [
                            "te",
                            "av",
                            "extraction"
                        ]
                    }
                ]
            })
        )
        logger.debug('Response HTTP Status Code: {status_code}'.format(
            status_code=response.status_code))
        logger.debug('Response HTTP Response Body: {content}'.format(
            content=response.content))
    except Exception as e:
        logger.error(traceback.format_exc())

    return response
