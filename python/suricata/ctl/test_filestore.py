from __future__ import print_function

import unittest

from suricata.ctl import filestore

class PruneTestCase(unittest.TestCase):

    def test_parse_age(self):
        self.assertEqual(filestore.parse_age("1s"), 1)
        self.assertEqual(filestore.parse_age("1m"), 60)
        self.assertEqual(filestore.parse_age("1h"), 3600)
        self.assertEqual(filestore.parse_age("1d"), 86400)

        with self.assertRaises(filestore.InvalidAgeFormatError):
            filestore.parse_age("1")
        with self.assertRaises(filestore.InvalidAgeFormatError):
            filestore.parse_age("1y")
