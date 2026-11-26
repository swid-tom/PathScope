import unittest
from unittest.mock import Mock, patch

from app.probes import geoip


class GeoIpEnrichmentTests(unittest.TestCase):
    def setUp(self):
        geoip._CACHE.clear()

    def tearDown(self):
        geoip._CACHE.clear()

    def test_parse_cymru_response_extracts_bgp_origin_and_handles_multiple_origins(self):
        response = (
            "AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name\n"
            "714 | 17.253.144.10 | 17.253.144.0/24 | US | arin | 2000-05-04 | APPLE - Apple Inc., US\n"
            "1299 | 17.253.144.10 | 17.253.144.0/24 | US | arin | 2000-05-04 | ARELION - Arelion, SE\n"
            "header | not-an-ip | not-a-prefix | - | - | - | -\n"
        )

        result = geoip._parse_cymru_response(response)

        self.assertEqual(
            result["17.253.144.10"],
            {
                "as": "AS714, AS1299",
                "bgp_prefix": "17.253.144.0/24",
                "asn_source": "Team Cymru",
                "org": "APPLE - Apple Inc., US; ARELION - Arelion, SE",
            },
        )

    @patch("app.probes.geoip._lookup_cymru_batch")
    @patch("app.probes.geoip.requests.post")
    def test_lookup_batch_merges_bgp_data_and_caches_public_ip_results(self, post, lookup_cymru):
        response = Mock()
        response.json.return_value = [
            {
                "query": "8.8.8.8",
                "country": "United States",
                "city": "Mountain View",
                "isp": "Google LLC",
                "org": "Google LLC",
                "as": "AS15169 Google LLC",
            }
        ]
        post.return_value = response
        lookup_cymru.return_value = {
            "8.8.8.8": {
                "as": "AS15169",
                "org": "GOOGLE - Google LLC, US",
                "bgp_prefix": "8.8.8.0/24",
                "asn_source": "Team Cymru",
            }
        }

        result = geoip.lookup_batch(["8.8.8.8", "172.18.0.1"], ttl_seconds=3600)
        cached = geoip.lookup_batch(["8.8.8.8", "172.18.0.1"], ttl_seconds=3600)

        self.assertEqual(result["8.8.8.8"]["as"], "AS15169")
        self.assertEqual(result["8.8.8.8"]["org"], "GOOGLE - Google LLC, US")
        self.assertEqual(result["8.8.8.8"]["bgp_prefix"], "8.8.8.0/24")
        self.assertEqual(result["8.8.8.8"]["asn_source"], "Team Cymru")
        self.assertNotIn("172.18.0.1", result)
        self.assertEqual(cached, result)
        post.assert_called_once()
        lookup_cymru.assert_called_once_with(["8.8.8.8"])

    def test_non_global_addresses_are_not_sent_to_public_lookup_services(self):
        self.assertFalse(geoip._is_public_ip("100.68.4.1"))
        self.assertFalse(geoip._is_public_ip("192.0.2.1"))
        self.assertTrue(geoip._is_public_ip("8.8.8.8"))


if __name__ == "__main__":
    unittest.main()
