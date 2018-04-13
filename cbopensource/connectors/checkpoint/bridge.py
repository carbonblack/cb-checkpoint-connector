from cbint.utils.detonation import DetonationDaemon, ConfigurationError
from cbint.utils.detonation.binary_analysis import (BinaryAnalysisProvider, AnalysisPermanentError,
                                                    AnalysisTemporaryError, AnalysisResult, AnalysisInProgress)
import cbint.utils.feed
import time
import logging
import os
import sys
from checkpoint_api import checkpoint_query

log = logging.getLogger(__name__)


class CheckpointProvider(BinaryAnalysisProvider):
    def __init__(self, name, checkpoint_url, checkpoint_ssl_verify, api_key, work_directory):
        super(CheckpointProvider, self).__init__(name)
        self.api_key = api_key
        self.checkpoint_url = checkpoint_url
        self.checkpoint_ssl_verify = checkpoint_ssl_verify
        self.current_api_key_index = 0
        self.work_directory = work_directory

    def _call_checkpoint_api(self, method, path, payload=None, files=None):
        url = self.checkpoint_url + path

        if method == 'GET':
            try:
                r = self.session.get(url, verify=self.checkpoint_ssl_verify)
            except Exception as e:
                log.exception("Exception when sending checkpoint API GET request: %s" % e)
                raise

            return r.status_code, r.content
        elif method == 'POST':
            try:
                r = self.session.post(url, data=payload, files=files, verify=self.checkpoint_ssl_verify)
            except Exception as e:
                log.exception("Exception when sending checkpoint API query: %s" % e)
                # bubble this up as necessary
                raise
            return r.status_code, r.content

    def query_checkpoint(self, md5sum):
        """
        query the checkpoint api to get a report on an md5
        """
        log.info("Querying checkpoint for md5sum %s" % md5sum)

        response = checkpoint_query(self.checkpoint_url, self.api_key, md5sum)

        status_code, content = self._call_checkpoint_api("POST", "/publicapi/get/verdict",
                                                         {'hash': md5sum.lower()})

        if status_code == 404:
            return None  # can't find the binary
        elif status_code != 200:
            log.info("Received unknown HTTP status code %d from checkpoint" % status_code)
            log.info("-> response content: %s" % content)
            raise AnalysisTemporaryError("Received unknown HTTP status code %d from checkpoint" % status_code,
                                         retry_in=120)

        response = etree.fromstring(content)

        # Return 0 Benign verdict
        # 1 Malware verdict
        # 2 Grayware verdict
        # -100 Verdict is pending
        # -101 Indicates a file error
        # -102 The file could not be found
        # -103 The hash submitted is invalid
        if md5sum.lower() == response.findtext("./get-verdict-info/md5").lower():
            verdict = response.findtext("./get-verdict-info/verdict").strip()
            if verdict == "-100":
                return None  # waiting for checkpoint verdict
            elif verdict == "-102":
                return None  # file not in checkpoint yet
            elif verdict.startswith("-"):
                raise AnalysisPermanentError("checkpoint could not process file: error %s" % verdict)
            elif verdict == "1":
                return self.generate_malware_result(md5sum, 100)
            elif verdict == "2":
                return self.generate_malware_result(md5sum, 50)
            else:
                return AnalysisResult(score=0)

    def generate_malware_result(self, md5, score):
        status_code, content = self._call_checkpoint_api("POST", "/publicapi/get/report",
                                                         {'hash': md5.lower(), "format": "pdf"})

        if status_code == 200:
            open(os.path.join(self.work_directory, md5.upper()) + ".pdf", 'wb').write(content)
            return AnalysisResult(score=score, link="/reports/%s.pdf" % md5.upper())
        else:
            return AnalysisResult(score=score)

    def submit_checkpoint(self, md5sum, file_stream):
        """
        submit a file to the checkpoint api
        returns a checkpoint submission status code
        """

        files = {'file': ('CarbonBlack_%s' % md5sum, file_stream)}
        try:
            status_code, content = self._call_checkpoint_api("POST", "/publicapi/submit/file", files=files)
        except Exception as e:
            log.exception("Exception while submitting MD5 %s to checkpoint: %s" % (md5sum, e))
            raise AnalysisTemporaryError("Exception while submitting to checkpoint: %s" % e)
        else:
            if status_code == 200:
                return True
            else:
                raise AnalysisTemporaryError("Received HTTP error code %d while submitting to checkpoint" % status_code)

    def check_result_for(self, md5sum):
        return self.query_checkpoint(md5sum)

    def analyze_binary(self, md5sum, binary_file_stream):
        self.submit_checkpoint(md5sum, binary_file_stream)

        retries = 20
        while retries:
            time.sleep(30)
            result = self.check_result_for(md5sum)
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
        return 0

    def get_provider(self):
        checkpoint_provider = CheckpointProvider(self.name,
                                                 self.checkpoint_url,
                                                 self.checkpoint_ssl_verify,
                                                 self.api_key,
                                                 self.work_directory)
        return checkpoint_provider

    def get_metadata(self):
        return cbint.utils.feed.generate_feed(self.name, summary="Checkpoint cloud binary feed",
                                              tech_data=(
                                                  "There are no requirements to share any data with Carbon Black to use this feed. "
                                                  "However, binaries may be shared with Palo Alto."),
                                              provider_url="http://checkpoint.paloaltonetworks.com/",
                                              icon_path='/usr/share/cb/integrations/checkpoint/checkpoint-logo.png',
                                              display_name="checkpoint", category="Connectors")

    def validate_config(self):
        super(CheckpointConnector, self).validate_config()

        self.api_key = self.get_config_string("checkpoint_api_key", None)
        if not self.api_key:
            raise ConfigurationError("checkpoint API key must be specified in the checkpoint_api_key option")

        checkpoint_url = self.get_config_string("checkpoint_url", "https://checkpoint.paloaltonetworks.com")
        self.checkpoint_url = checkpoint_url.rstrip("/")

        self.checkpoint_ssl_verify = self.get_config_boolean("checkpoint_verify_ssl", True)

        log.info("connecting to checkpoint server at %s with API key %s" % (self.checkpoint_url, self.api_key))

        return True


if __name__ == '__main__':
    import logging

    logging.basicConfig(level=logging.DEBUG)

    my_path = os.path.dirname(os.path.abspath(__file__))
    temp_directory = "/tmp/checkpoint"

    config_path = os.path.join(my_path, "testing.conf")
    daemon = CheckpointConnector('checkpointtest',
                                 configfile=config_path,
                                 work_directory=temp_directory,
                                 logfile=os.path.join(temp_directory, 'test.log'),
                                 debug=True)
    daemon.start()
