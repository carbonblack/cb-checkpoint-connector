import requests
import logging
import json
import traceback

logger = logging.getLogger(__name__)


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
