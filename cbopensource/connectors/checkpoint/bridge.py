from cbint.utils.detonation import DetonationDaemon, ConfigurationError
from cbint.utils.detonation.binary_analysis import (BinaryAnalysisProvider, AnalysisPermanentError,
                                                    AnalysisTemporaryError, AnalysisResult, AnalysisInProgress)
import cbint.utils.feed
import time
import logging
import os
import sys
from cbapi.connection import CbAPISessionAdapter
from checkpoint_api import APISession
import json
import traceback
from cStringIO import StringIO

log = logging.getLogger(__name__)


class CheckpointProvider(BinaryAnalysisProvider):
    def __init__(self, name, checkpoint_url, checkpoint_ssl_verify, api_key, work_directory):
        super(CheckpointProvider, self).__init__(name)
        self.api_key = api_key
        self.checkpoint_url = checkpoint_url
        self.checkpoint_ssl_verify = checkpoint_ssl_verify
        self.current_api_key_index = 0
        self.work_directory = work_directory
        self.session = APISession(api_key=self.api_key, throttle_per_minute=120)
        tls_adapter = CbAPISessionAdapter(force_tls_1_2=True)
        self.session.mount("https://", tls_adapter)

    def _call_checkpoint_api(self, method, path, headers, payload=None, files=None):
        url = self.checkpoint_url + path
        self.session.headers = {}
        self.session.headers.update(headers)

        if method == 'GET':
            try:

                r = self.session.get(url, verify=self.checkpoint_ssl_verify)
            except Exception as e:
                log.error("Exception when sending checkpoint API GET request: %s" % str(e))
                raise

            return r.status_code, r.content
        elif method == 'POST':
            try:
                r = self.session.post(url, data=payload, files=files, verify=self.checkpoint_ssl_verify)
            except Exception as e:
                log.error("Exception when sending checkpoint API query: %s" % str(e))
                # bubble this up as necessary
                raise
            return r.status_code, r.content

    def query_checkpoint(self, md5sum):
        """
        query the checkpoint api to get a report on an md5
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": self.api_key,
        }

        payload = json.dumps({
            "request": [
                {
                    "md5": md5sum,
                    "features": [
                        "te",
                        "av",
                        "extraction"
                    ]
                }
            ]
        })

        log.info("Querying checkpoint for md5sum %s" % md5sum)

        try:
            status_code, content = self._call_checkpoint_api(method="POST",
                                                             path="/tecloud/api/v1/file/query",
                                                             headers=headers,
                                                             payload=payload,
                                                             files=None)

            if status_code != 200:
                log.info("Received unknown HTTP status code %d from checkpoint" % status_code)
                log.info("-> response content: %s" % content)
                raise AnalysisTemporaryError("Received unknown HTTP status code %d from checkpoint" % status_code,
                                             retry_in=120)
        except Exception as e:
            log.info(str(e))
            raise AnalysisTemporaryError("There was an error connecting to Checkpoint %s" % str(e),
                                         retry_in=120)

        dict_response = json.loads(content)
        try:
            checkpoint_status_code = dict_response.get("response", [])[0].get("te", {}).get("status", {}).get("code",
                                                                                                              -1)
        except Exception as e:
            checkpoint_status_code = -1
            log.error("Failed to parse checkpoint response JSON")
            log.error(traceback.format_exc())

        log.info("md5: {0} returned status_code: {1}".format(md5sum,checkpoint_status_code))
        log.info(content)

        if checkpoint_status_code == 1001:

            severity = dict_response.get("response", [])[0].get("te", {}).get("combined_verdict", None)

            if severity.lower() == "malicious":
                score = 100
            elif severity.lower() == "unknown":
                return None
            elif severity.lower() == "benign":
                score = 0
            else:
                return None

            log.info("{0} has score of {1}".format(md5sum, score))
            return AnalysisResult(score=score)

        elif checkpoint_status_code == 1003:
            #
            # Pending
            #
            return None
        elif checkpoint_status_code == 1004:
            #
            # 1004 NOT_Found
            # File is not in checkpoint yet
            #
            return None
        elif checkpoint_status_code == 1005:
            #
            # Out of Quota
            #
            return AnalysisTemporaryError("Out of Quota")
        elif checkpoint_status_code == 1006:
            #
            # Partially found
            #
            return None
        elif checkpoint_status_code == 1007:
            #
            # FILE_TYPE_NOT_SUPPORTED
            #
            return AnalysisPermanentError("Filetype is not supported")
        elif checkpoint_status_code == 1009:
            #
            # Internal Error
            #
            return AnalysisTemporaryError("Internal Error from Checkpoint")
        elif checkpoint_status_code == 1011:
            #
            # Insufficient resources
            #
            return AnalysisTemporaryError("Checkpoint reports insufficient resources")
        else:
            return None

    def submit_checkpoint(self, md5sum, file_stream):
        """
        submit a file to the checkpoint api
        returns a checkpoint submission status code
        """

        headers = {
            "Authorization": self.api_key,
        }

        payload = {"request": {
            "md5": md5sum,
            "file_name": "CarbonBlack_{0}".format(md5sum)
        }}

        json_input = StringIO(json.dumps(payload))

        files = {'file': ("CarbonBlack_{0}".format(md5sum), file_stream), 'request': ('request', json_input)}

        log.info("Submitting {0} to Checkpoint Threat Emulation".format(md5sum))

        try:
            status_code, content = self._call_checkpoint_api("POST",
                                                             "/tecloud/api/v1/file/upload",
                                                             headers=headers,
                                                             payload=None,
                                                             files=files)
        except Exception as e:
            log.exception("Exception while submitting MD5 %s to checkpoint: %s" % (md5sum, e))
            raise AnalysisTemporaryError("Exception while submitting to checkpoint: %s" % e)
        else:
            if status_code == 200:
                return True
            else:
                time.sleep(5)
                raise AnalysisTemporaryError("Received HTTP error code %d while submitting to checkpoint" % status_code)

    def check_result_for(self, md5sum):
        return None
        # return self.query_checkpoint(md5sum)

    def analyze_binary(self, md5sum, binary_file_stream):
        self.submit_checkpoint(md5sum, binary_file_stream)

        retries = 30
        while retries:
            time.sleep(10)
            result = self.query_checkpoint(md5sum)
            if result:
                return result
            retries -= 1

        raise AnalysisTemporaryError(message="Maximum retries (20) exceeded submitting to checkpoint", retry_in=120)


class CheckpointConnector(DetonationDaemon):
    @property
    def filter_spec(self):
        filters = []
        max_module_len = 10 * 1024 * 1024
        filters.append('(os_type:windows) orig_mod_len:[1 TO %d]' % max_module_len)
        additional_filter_requirements = self.get_config_string("binary_filter_query", None)
        if additional_filter_requirements:
            filters.append(additional_filter_requirements)

        log.info("Filter spec is %s" % ' '.join(filters))

        return ' '.join(filters)

    @property
    def integration_name(self):
        return 'Cb Checkpoint Connector 1.0.0'

    @property
    def num_quick_scan_threads(self):
        return 1

    @property
    def num_deep_scan_threads(self):
        return 1

    def get_provider(self):
        checkpoint_provider = CheckpointProvider(self.name,
                                                 self.checkpoint_url,
                                                 self.checkpoint_ssl_verify,
                                                 self.api_key,
                                                 self.work_directory)
        return checkpoint_provider

    def get_metadata(self):
        return cbint.utils.feed.generate_feed(self.name,
                                              summary="Checkpoint cloud binary feed",
                                              tech_data=(
                                                  "There are no requirements to share any data with Carbon Black"
                                                  "to use this feed. However, binaries may be shared with Checkpoint."),
                                              provider_url="http://www.checkpoint.com/",
                                              icon_path='/usr/share/cb/integrations/checkpoint/checkpoint-logo.png',
                                              display_name="checkpoint", category="Connectors")

    def validate_config(self):
        super(CheckpointConnector, self).validate_config()

        self.api_key = self.get_config_string("checkpoint_api_key", None)
        if not self.api_key:
            raise ConfigurationError("Checkpoint API key must be specified in the checkpoint_api_key option")

        checkpoint_url = self.get_config_string("checkpoint_url", "https://te.checkpoint.com")
        self.checkpoint_url = checkpoint_url.rstrip("/")

        self.checkpoint_ssl_verify = True

        log.debug("connecting to checkpoint server at %s with API key %s" % (self.checkpoint_url, self.api_key))

        return True


if __name__ == '__main__':
    import logging

    logging.basicConfig(level=logging.DEBUG)

    my_path = os.path.dirname(os.path.abspath(__file__))
    temp_directory = "/tmp/checkpoint"

    # /private/tmp/checkpoint/sqlite.db

    config_path = "testing.conf"
    daemon = CheckpointConnector('checkpointtest',
                                 configfile=config_path,
                                 work_directory=temp_directory,
                                 logfile=os.path.join(temp_directory, 'test.log'),
                                 debug=True)
    daemon.start()
