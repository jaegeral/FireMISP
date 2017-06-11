import unittest

from pyFireEyeAlert import *
#from firemisp_settings import *

import fmtest

class PrimesTestCase(unittest.TestCase):
    """Tests for `primes.py`."""

    def test_is_isight_working(self):
        #serverurl = 'http://' + url + ':' + port

        """Is test api there aka connection test"""
        self.assertTrue(fmtest.processFile(inputfile='alert_details_fireeye_reducted.json',serverurl='http://127.0.0.1:8081'))


if __name__ == '__main__':
    unittest.main()