import unittest
#check_misp_two_criterias
from firemisp_settings import *


class OfflineTestCases(unittest.TestCase):

    def test_check_two_conditions_for_misp(self):
        from firemisp import init_misp, check_misp_two_criterias

        misp = init_misp(misp_url, misp_key)

        result = check_misp_two_criterias(misp, "41856", "4325869102")

        self.assertIsNot(result,False,"Message is false, something went wrong")


class PrimesTestCase(unittest.TestCase):



    def test_is_misp_running(self):
        # is MISp running?
        #from firemisp import init_misp

        #misp = init_misp(misp_url, misp_key)
        self.assertIsNotNone(PyMISP(misp_url, misp_key, False, 'json'))

    def test_is_firemisp_webserver_running(self):
        # is MISp running?
        # from firemisp import init_misp

        import urllib.request

        firemisp_ip = config.get('FireMisp', 'httpServerIP')
        firemisp_port = config.getint('FireMisp', 'httpServerPort')

        url=str("http://"+firemisp_ip+":"+str(firemisp_port)+"/ping")


        try:
            with urllib.request(url) as response:
                html = response.read()
        except urllib.error.HTTPError as e:
            self.assertIsNot(e.code,200)

    def test_is_isight_working(self):
        #serverurl = 'http://' + url + ':' + port

        import fmtest
        """Is test api there aka connection test"""
        self.assertTrue(fmtest.processFile(inputfile='alert_details_fireeye_reducted.json',serverurl='http://127.0.0.1:8081'))



if __name__ == '__main__':
    unittest.main()