import unittest
import json
import time
from unittest.mock import MagicMock
from mock import patch


class TestDatastoreClient(unittest.TestCase):

    def test_generate_datastore_session_sucess(self):
        # with patch("metadata_cache.org_metadata_cache.OrgMetadataCache._get_redis_vcap") as mock_get_redis_vcap,
        return True

    def test_generate_datastore_session_failure(self):
        return True

    def test_execute_query_success(self):
        return True

    def test_execute_query_failure(self):
        return True

    def test_close_session_success(self):
        return True

    def test_close_session_exception(self):
        return True
