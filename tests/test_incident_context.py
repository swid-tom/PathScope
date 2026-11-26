import datetime as dt
import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import main
from app.main import TargetCreate
from app.config import TargetConfig
from app.db import Base, Run
from app.probes import incident_context
from app import scheduler


class IncidentContextTests(unittest.TestCase):
    def test_status_page_discovery_prefers_manual_override_and_recognizes_providers(self):
        manual = incident_context._discover_status_page(
            "github.com",
            "https://manual.example/api/v2/summary.json",
        )
        self.assertEqual(manual["url"], "https://manual.example/api/v2/summary.json")
        self.assertEqual(manual["source"], "Manual configuration")

        known = incident_context._discover_status_page("api.github.com", None)
        self.assertEqual(known["url"], "https://www.githubstatus.com/api/v2/summary.json")
        self.assertEqual(known["provider"], "GitHub Status")
        self.assertEqual(known["confidence"], "high")

        statuspage = incident_context._discover_status_page("example.statuspage.io", None)
        self.assertEqual(statuspage["url"], "https://example.statuspage.io/api/v2/summary.json")
        self.assertEqual(statuspage["provider"], "Atlassian Statuspage")

    def test_status_page_discovery_uses_conventional_endpoint_only_for_apex_hosts(self):
        conventional = incident_context._discover_status_page("www.example.com", None)
        self.assertEqual(conventional["url"], "https://status.example.com/api/v2/summary.json")
        self.assertEqual(conventional["source"], "Conventional status subdomain")
        self.assertEqual(conventional["confidence"], "medium")

        self.assertIsNone(incident_context._discover_status_page("api.example.com", None)["url"])
        self.assertIsNone(incident_context._discover_status_page("8.8.8.8", None)["url"])

    def test_status_page_url_requires_https_without_credentials_or_nonstandard_port(self):
        self.assertEqual(
            incident_context.normalize_status_page_url(" https://status.example/api/v2/summary.json "),
            "https://status.example/api/v2/summary.json",
        )
        for value in (
            "http://status.example/summary.json",
            "https://user:password@status.example/summary.json",
            "https://status.example:8443/summary.json",
            "https://status.example/summary.json?token=secret",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                incident_context.normalize_status_page_url(value)

        with self.assertRaises(ValidationError):
            TargetCreate(host="example.com", status_page_url="http://status.example/summary.json")

    @patch("app.probes.incident_context.requests.get")
    def test_bgplay_and_rpki_use_public_prefix_and_origin(self, get):
        bgp_response = Mock()
        bgp_response.status_code = 200
        bgp_payload = {
            "status": "ok",
            "data": {
                "initial_state": [
                    {"path": [6453, 714]},
                    {"path": ["174", "714"]},
                ],
                "events": [
                    {
                        "timestamp": "2026-01-01T12:00:00",
                        "type": "W",
                        "attrs": {"source_id": "collector-peer"},
                    }
                ],
            },
        }
        bgp_response.iter_content.return_value = [json.dumps(bgp_payload).encode()]
        rpki_response = Mock()
        rpki_response.status_code = 200
        rpki_response.iter_content.return_value = [
            json.dumps({"status": "ok", "data": {"status": "unknown"}}).encode()
        ]
        get.side_effect = [bgp_response, rpki_response]

        context = incident_context.collect_incident_context(
            event_time=dt.datetime(2026, 1, 1, 12),
            trigger_reasons=["path_change"],
            local={"path_changed": True},
            prefix="17.253.144.0/24",
            origin_asns=["AS714"],
            status_page_url=None,
        )

        self.assertEqual(context["bgp"]["event_count"], 1)
        self.assertEqual(context["bgp"]["observed_origins"], ["714"])
        self.assertEqual(context["rpki"][0]["status"], "unknown")
        self.assertEqual(context["assessment"]["confidence"], "suggestive")
        self.assertEqual(get.call_args_list[1].kwargs["params"], {
            "resource": "714",
            "prefix": "17.253.144.0/24",
        })

    @patch("app.probes.incident_context.socket.getaddrinfo")
    @patch("app.probes.incident_context.requests.get")
    def test_status_page_is_bounded_and_reports_only_active_incidents(self, get, getaddrinfo):
        getaddrinfo.return_value = [(None, None, None, None, ("8.8.8.8", 443))]
        response = Mock()
        response.status_code = 200
        response.iter_content.return_value = [
            json.dumps(
                {
                    "status": {"indicator": "major", "description": "Service disruption"},
                    "incidents": [
                        {"name": "Current issue", "status": "investigating"},
                        {"name": "Resolved issue", "status": "resolved"},
                    ],
                }
            ).encode()
        ]
        get.return_value = response

        context = incident_context.collect_incident_context(
            event_time=dt.datetime(2026, 1, 1, 12),
            trigger_reasons=["endpoint_failure"],
            local={"path_changed": False},
            prefix=None,
            origin_asns=[],
            status_page_url="https://status.example/api/v2/summary.json",
        )

        self.assertEqual(context["status_page"]["indicator"], "major")
        self.assertEqual(len(context["status_page"]["active_incidents"]), 1)
        self.assertEqual(context["status_page_discovery"]["source"], "Manual configuration")
        self.assertEqual(context["status_page_discovery"]["confidence"], "high")
        self.assertEqual(context["assessment"]["confidence"], "corroborated")
        self.assertTrue(get.call_args.kwargs["stream"])
        self.assertFalse(get.call_args.kwargs["allow_redirects"])

    @patch("app.probes.incident_context.socket.getaddrinfo")
    @patch("app.probes.incident_context.requests.get")
    def test_auto_discovery_verifies_statuspage_shape_and_reports_source(self, get, getaddrinfo):
        getaddrinfo.return_value = [(None, None, None, None, ("8.8.8.8", 443))]
        response = Mock()
        response.status_code = 200
        response.iter_content.return_value = [
            json.dumps(
                {
                    "status": {"indicator": "none", "description": "All systems operational"},
                    "incidents": [],
                }
            ).encode()
        ]
        get.return_value = response

        context = incident_context.collect_incident_context(
            event_time=dt.datetime(2026, 1, 1, 12),
            trigger_reasons=["path_change"],
            local={"target": "www.example.com", "path_changed": True},
            prefix=None,
            origin_asns=[],
            status_page_url=None,
        )

        self.assertEqual(get.call_args.args[0], "https://status.example.com/api/v2/summary.json")
        self.assertEqual(context["status_page"]["status"], "available")
        self.assertEqual(context["status_page_discovery"]["status"], "verified")
        self.assertEqual(context["status_page_discovery"]["source"], "Conventional status subdomain")
        self.assertEqual(context["status_page_discovery"]["confidence"], "medium")
        self.assertEqual(context["assessment"]["confidence"], "inconclusive")

    @patch("app.probes.incident_context.socket.getaddrinfo")
    @patch("app.probes.incident_context.requests.get")
    def test_auto_discovery_does_not_accept_unrelated_json(self, get, getaddrinfo):
        getaddrinfo.return_value = [(None, None, None, None, ("8.8.8.8", 443))]
        response = Mock()
        response.status_code = 200
        response.iter_content.return_value = [b'{"message":"unrelated JSON"}']
        get.return_value = response

        context = incident_context.collect_incident_context(
            event_time=dt.datetime(2026, 1, 1, 12),
            trigger_reasons=["endpoint_failure"],
            local={"target": "example.com"},
            prefix=None,
            origin_asns=[],
            status_page_url=None,
        )

        self.assertEqual(context["status_page"]["status"], "unavailable")
        self.assertEqual(context["status_page_discovery"]["status"], "unavailable")
        self.assertEqual(context["status_page"]["url"], "https://status.example.com/api/v2/summary.json")

    @patch("app.probes.incident_context.socket.getaddrinfo")
    @patch("app.probes.incident_context.requests.get")
    def test_status_page_refuses_private_dns_results(self, get, getaddrinfo):
        getaddrinfo.return_value = [(None, None, None, None, ("127.0.0.1", 443))]

        context = incident_context.collect_incident_context(
            event_time=dt.datetime(2026, 1, 1, 12),
            trigger_reasons=["dns_failure"],
            local={},
            prefix=None,
            origin_asns=[],
            status_page_url="https://status.example/api/v2/summary.json",
        )

        get.assert_not_called()
        self.assertEqual(context["status_page"]["status"], "unavailable")

    @patch("app.scheduler.incident_context.collect_incident_context")
    @patch("app.scheduler.dns_probe.resolve", return_value=([], None, "DNS timeout"))
    def test_scheduler_records_context_only_when_failure_begins(self, _resolve, collect):
        collect.return_value = {"assessment": {"confidence": "inconclusive"}}
        engine = create_engine("sqlite:///:memory:")
        try:
            Base.metadata.create_all(engine)
            session = sessionmaker(bind=engine, expire_on_commit=False)()
            with patch("app.scheduler.SessionLocal", return_value=session):
                scheduler.probe_target(
                    TargetConfig(host="example.com", label="Example"),
                    SimpleNamespace(dns_sinkhole_ranges=[], geoip_enabled=False, alert_enabled=False),
                )
                scheduler.probe_target(
                    TargetConfig(host="example.com", label="Example"),
                    SimpleNamespace(dns_sinkhole_ranges=[], geoip_enabled=False, alert_enabled=False),
                )

            runs = session.query(Run).order_by(Run.id).all()
            self.assertEqual(len(runs), 2)
            self.assertIsNotNone(runs[0].incident_context_json)
            self.assertIsNone(runs[1].incident_context_json)
            collect.assert_called_once()
            self.assertEqual(collect.call_args.kwargs["trigger_reasons"], ["dns_failure"])
            session.close()
        finally:
            engine.dispose()

    def test_context_api_returns_latest_event_not_latest_probe(self):
        engine = create_engine("sqlite:///:memory:")
        try:
            Base.metadata.create_all(engine)
            session = sessionmaker(bind=engine, expire_on_commit=False)()
            now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
            session.add_all(
                [
                    Run(
                        target="example.com",
                        timestamp=now - dt.timedelta(minutes=1),
                        success=False,
                        incident_context_json='{"trigger_reasons":["mtr_failure"]}',
                    ),
                    Run(target="example.com", timestamp=now, success=True),
                ]
            )
            session.commit()

            with patch("app.main.SessionLocal", return_value=session):
                result = main.api_incident_context(target="example.com", window="24h")

            self.assertEqual(result["context"]["trigger_reasons"], ["mtr_failure"])
            self.assertIsNotNone(result["timestamp"])
            session.close()
        finally:
            engine.dispose()

    def test_events_api_returns_recent_snapshots_and_can_select_an_event(self):
        engine = create_engine("sqlite:///:memory:")
        try:
            Base.metadata.create_all(engine)
            session = sessionmaker(bind=engine, expire_on_commit=False)()
            older = Run(
                target="example.com",
                timestamp=dt.datetime(2026, 1, 1, 12),
                incident_context_json='{"trigger_reasons":["path_change"]}',
            )
            newer = Run(
                target="example.com",
                timestamp=dt.datetime(2026, 1, 1, 13),
                incident_context_json='{"trigger_reasons":["endpoint_failure"]}',
            )
            session.add_all(
                [
                    older,
                    newer,
                    Run(
                        target="other.example",
                        timestamp=dt.datetime(2026, 1, 1, 14),
                        incident_context_json='{"trigger_reasons":["dns_failure"]}',
                    ),
                    Run(
                        target="example.com",
                        timestamp=dt.datetime(2026, 1, 1, 15),
                    ),
                ]
            )
            session.commit()

            with patch("app.main.SessionLocal", return_value=session):
                result = main.api_events(
                    limit=4,
                    target="example.com",
                    event_id=None,
                    window=None,
                    start=None,
                    end=None,
                    _auth=None,
                )
                focused = main.api_events(
                    limit=1,
                    target=None,
                    event_id=older.id,
                    window=None,
                    start=None,
                    end=None,
                    _auth=None,
                )

            self.assertEqual([event["id"] for event in result], [newer.id, older.id])
            self.assertEqual(focused[0]["id"], older.id)
            self.assertEqual(focused[0]["context"]["trigger_reasons"], ["path_change"])
            session.close()
        finally:
            engine.dispose()

    @patch("app.scheduler.incident_context.collect_incident_context")
    @patch("app.scheduler.port_probe.tcp_check", return_value=(False, None, "connection refused"))
    @patch(
        "app.scheduler.mtr_probe.run_mtr",
        return_value=([{"count": 1, "host": "8.8.8.8", "Loss%": 0, "Snt": 5}], None),
    )
    @patch("app.scheduler.dns_probe.resolve", return_value=(["8.8.8.8"], 1.0, None))
    def test_scheduler_records_configured_service_failures(
        self, _resolve, _mtr, _tcp_check, collect
    ):
        collect.return_value = {"assessment": {"confidence": "inconclusive"}}
        engine = create_engine("sqlite:///:memory:")
        try:
            Base.metadata.create_all(engine)
            session = sessionmaker(bind=engine, expire_on_commit=False)()
            config = SimpleNamespace(
                dns_sinkhole_ranges=[],
                geoip_enabled=False,
                mtr_count=5,
                mtr_protocol="tcp",
                mtr_port=443,
                endpoint_probe_enabled=False,
                tls_enabled=False,
                port_timeout_seconds=3,
                stun_enabled=False,
                alert_enabled=False,
            )
            with patch("app.scheduler.SessionLocal", return_value=session):
                scheduler.probe_target(
                    TargetConfig(host="example.com", label="Example", tcp_ports=[443]),
                    config,
                )

            run = session.query(Run).one()
            self.assertTrue(run.success)
            self.assertEqual(
                collect.call_args.kwargs["trigger_reasons"],
                ["service_failure"],
            )
            self.assertEqual(
                collect.call_args.kwargs["local"]["service_checks"],
                [
                    {
                        "protocol": "tcp",
                        "port": 443,
                        "success": False,
                        "error": "connection refused",
                    }
                ],
            )
            session.close()
        finally:
            engine.dispose()


if __name__ == "__main__":
    unittest.main()
