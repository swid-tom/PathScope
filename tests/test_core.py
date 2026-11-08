import datetime as dt
import errno
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException
from fastapi.security import HTTPBasicCredentials
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.requests import Request
import yaml

from app.config import TargetConfig, load_config
from app.config_store import update_config_file, update_config_section
from app.db import AlertEvent, Base, Hop, PortCheck, Run
from app import main
from app.main import _sample_chart_runs, _time_range
from app.queries import (
    classify_status,
    effective_path_hop,
    effective_path_hops,
    service_reachability,
)
from app.scheduler import _evaluate_alerts


class CoreBehaviorTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.session = sessionmaker(bind=self.engine, expire_on_commit=False)()

    def tearDown(self):
        self.session.close()
        self.engine.dispose()

    def add_run(self, **values):
        values.setdefault("target", "monitor.example")
        values.setdefault("timestamp", dt.datetime(2026, 1, 1))
        values.setdefault("success", True)
        run = Run(**values)
        self.session.add(run)
        self.session.flush()
        return run

    def test_effective_hops_are_loaded_in_bulk_and_ignore_unresponsive_hops(self):
        first = self.add_run()
        second = self.add_run(timestamp=dt.datetime(2026, 1, 2))
        self.session.add_all(
            [
                Hop(run_id=first.id, hop_num=1, host="192.0.2.1", avg_ms=10, loss_pct=0),
                Hop(run_id=first.id, hop_num=2, host="???", avg_ms=None, loss_pct=100),
                Hop(run_id=first.id, hop_num=3, host="192.0.2.3", avg_ms=30, loss_pct=0),
                Hop(run_id=second.id, hop_num=1, host="???", avg_ms=None, loss_pct=100),
            ]
        )
        self.session.flush()

        effective = effective_path_hops(self.session, [first.id, second.id])

        self.assertEqual(effective[first.id].hop_num, 3)
        self.assertEqual(effective[second.id].hop_num, 1)
        self.assertEqual(effective_path_hop(self.session, first.id).avg_ms, 30)

    def test_empty_service_checks_do_not_report_false_unreachable(self):
        run = Run(
            success=True,
            endpoint_probe_protocol="tcp/443",
            endpoint_avg_ms=12.0,
            endpoint_error=None,
        )
        self.assertTrue(service_reachability(run, []))
        self.assertIsNone(service_reachability(Run(success=True), []))
        self.assertFalse(service_reachability(run, [PortCheck(success=False)]))

    def test_status_classification_distinguishes_unconfigured_services(self):
        status, reasons = classify_status(None, None, None, 150, 300, 2, 10)
        self.assertEqual(status, "green")
        self.assertEqual(reasons, [])

        status, reasons = classify_status(None, None, False, 150, 300, 2, 10)
        self.assertEqual(status, "red")
        self.assertEqual(reasons, ["service port unreachable"])

    def test_api_status_uses_endpoint_probe_when_no_service_ports_are_configured(self):
        run = self.add_run(
            endpoint_probe_protocol="tcp/443",
            endpoint_avg_ms=12.0,
            endpoint_error=None,
        )
        self.session.commit()
        session_factory = sessionmaker(bind=self.engine, expire_on_commit=False)

        with patch.object(main, "SessionLocal", session_factory):
            result = main.api_status(
                target=run.target,
                latency_warning_ms=150,
                latency_critical_ms=300,
                loss_warning_pct=2,
                loss_critical_pct=10,
                _auth=None,
            )

        self.assertEqual(result["status"], "green")
        self.assertTrue(result["service_reachable"])

        no_service_probe = self.add_run(
            target="without-checks.example",
            endpoint_probe_protocol=None,
            endpoint_avg_ms=None,
        )
        self.session.commit()
        with patch.object(main, "SessionLocal", session_factory):
            result = main.api_status(
                target=no_service_probe.target,
                latency_warning_ms=150,
                latency_critical_ms=300,
                loss_warning_pct=2,
                loss_critical_pct=10,
                _auth=None,
            )
        self.assertEqual(result["status"], "green")
        self.assertIsNone(result["service_reachable"])

    def test_time_range_rejects_bad_windows_and_custom_dates(self):
        for window, start, end in (
            ("invalid", None, None),
            ("custom", None, None),
            ("custom", "not-a-date", None),
            ("custom", "2026-01-02T00:00:00Z", "2026-01-01T00:00:00Z"),
        ):
            with self.subTest(window=window, start=start, end=end):
                with self.assertRaises(HTTPException) as raised:
                    _time_range(window, start, end)
                self.assertEqual(raised.exception.status_code, 400)

    def test_read_api_auth_is_opt_in_and_requires_configured_admin_credentials(self):
        with patch.object(main.cfg, "read_api_auth_required", False):
            main.require_read_api_auth(None)

        with patch.multiple(
            main.cfg,
            read_api_auth_required=True,
            admin_auth_enabled=False,
            admin_auth_password_sha256=None,
        ):
            with self.assertRaises(HTTPException) as raised:
                main.require_read_api_auth(None)
            self.assertEqual(raised.exception.status_code, 503)

        with patch.multiple(
            main.cfg,
            read_api_auth_required=True,
            admin_auth_enabled=True,
            admin_auth_username="admin",
            admin_auth_password_sha256=hashlib.sha256(b"secret").hexdigest(),
        ):
            main.require_read_api_auth(HTTPBasicCredentials(username="admin", password="secret"))
            with self.assertRaises(HTTPException) as raised:
                main.require_read_api_auth(HTTPBasicCredentials(username="admin", password="wrong"))
            self.assertEqual(raised.exception.status_code, 401)

        protected_paths = {
            "/api/targets",
            "/api/maintenance/stats",
            "/api/status",
            "/api/latest",
            "/api/alerts",
            "/api/summary",
            "/api/runs",
            "/api/runs/{run_id}/hops",
            "/api/export.csv",
        }
        write_paths = [
            ("/api/targets", "POST"),
            ("/api/targets/{host}", "PUT"),
            ("/api/targets/{host}", "DELETE"),
            ("/api/settings/retention", "PUT"),
            ("/api/maintenance/prune", "POST"),
            ("/api/maintenance/vacuum", "POST"),
            ("/api/alerts", "DELETE"),
        ]
        for path in protected_paths:
            with self.subTest(path=path):
                route = next(route for route in main.app.routes if getattr(route, "path", None) == path)
                self.assertIn(
                    main.require_read_api_auth,
                    [dependency.call for dependency in route.dependant.dependencies],
                )
        for path, method in write_paths:
            with self.subTest(path=path, method=method):
                route = next(
                    route
                    for route in main.app.routes
                    if getattr(route, "path", None) == path and method in route.methods
                )
                self.assertIn(
                    main.require_admin_ready,
                    [dependency.call for dependency in route.dependant.dependencies],
                )
        password_route = next(
            route for route in main.app.routes
            if getattr(route, "path", None) == "/api/admin/password"
        )
        self.assertIn(
            main.require_admin,
            [dependency.call for dependency in password_route.dependant.dependencies],
        )

    def test_bootstrap_password_is_hashed_and_forced_rotation_is_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.yaml"
            config_path.write_text(
                "admin_auth:\n  enabled: true\n  username: admin\n  password_sha256: null\n",
                encoding="utf-8",
            )
            with (
                patch.object(main, "CONFIG_PATH", str(config_path)),
                patch.multiple(
                    main.cfg,
                    admin_auth_enabled=True,
                    admin_auth_password_sha256=None,
                    admin_auth_password_change_required=False,
                ),
            ):
                main._initialize_bootstrap_admin_password()
                saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
                main.require_admin(
                    HTTPBasicCredentials(username="admin", password="password")
                )

        self.assertEqual(
            saved["admin_auth"]["password_sha256"],
            main.BOOTSTRAP_ADMIN_PASSWORD_SHA256,
        )
        self.assertTrue(saved["admin_auth"]["password_change_required"])

    def test_password_change_persists_hash_and_disables_forced_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.yaml"
            config_path.write_text(
                "admin_auth:\n  enabled: true\n  username: admin\n  password_sha256: old-hash\n",
                encoding="utf-8",
            )
            with (
                patch.object(main, "CONFIG_PATH", str(config_path)),
                patch.dict(os.environ, {"PATHSCOPE_ADMIN_PASSWORD_SHA256": ""}),
                patch.multiple(
                    main.cfg,
                    admin_auth_enabled=True,
                    admin_auth_password_sha256="old-hash",
                    admin_auth_password_change_required=True,
                ),
            ):
                response = main.api_change_admin_password(
                    main.AdminPasswordChange(new_password="a-strong-new-password"),
                    _auth=None,
                )
                saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
                main.require_admin(
                    HTTPBasicCredentials(username="admin", password="a-strong-new-password")
                )

        expected_hash = hashlib.sha256(b"a-strong-new-password").hexdigest()
        self.assertEqual(response, {"password_updated": True})
        self.assertEqual(saved["admin_auth"]["password_sha256"], expected_hash)
        self.assertFalse(saved["admin_auth"]["password_change_required"])

    def test_admin_ready_guard_blocks_actions_until_password_rotated(self):
        with (
            patch.multiple(
                main.cfg,
                admin_auth_enabled=True,
                admin_auth_username="admin",
                admin_auth_password_sha256=hashlib.sha256(b"password").hexdigest(),
                admin_auth_password_change_required=True,
            ),
        ):
            with self.assertRaises(HTTPException) as raised:
                main.require_admin_ready(
                    HTTPBasicCredentials(username="admin", password="password")
                )
        self.assertEqual(raised.exception.status_code, 403)

    def test_admin_template_only_shows_password_form_during_forced_change(self):
        request = Request({"type": "http", "method": "GET", "path": "/admin", "headers": []})
        template = main.templates.env.get_template("admin.html")

        forced_html = template.render(
            request=request,
            admin_auth_enabled=True,
            password_change_required=True,
            env_password_managed=False,
        )
        self.assertIn("Change the default admin password", forced_html)
        self.assertNotIn('id="targetForm"', forced_html)

        normal_html = template.render(
            request=request,
            admin_auth_enabled=True,
            password_change_required=False,
            env_password_managed=False,
        )
        self.assertIn('id="targetForm"', normal_html)
        self.assertIn('id="passwordForm"', normal_html)

    def test_chart_sampling_caps_points_and_keeps_range_endpoints(self):
        runs = [Run(id=index) for index in range(4001)]

        sampled = _sample_chart_runs(runs)

        self.assertEqual(len(sampled), 2000)
        self.assertEqual(sampled[0].id, runs[0].id)
        self.assertEqual(sampled[-1].id, runs[-1].id)

    def test_config_updates_replace_atomically_and_preserve_other_values(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.yaml"
            config_path.write_text("targets: []\nretention_days: 30\n", encoding="utf-8")

            update_config_file(str(config_path), {"retention_days": 14})

            self.assertIn("retention_days: 14", config_path.read_text(encoding="utf-8"))
            self.assertIn("targets: []", config_path.read_text(encoding="utf-8"))
            self.assertEqual(list(Path(directory).iterdir()), [config_path])

    def test_config_update_supports_bind_mounts_that_reject_atomic_replace(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.yaml"
            config_path.write_text("admin_auth:\n  enabled: true\n", encoding="utf-8")
            with patch(
                "app.config_store.os.replace",
                side_effect=OSError(errno.EBUSY, "device or resource busy"),
            ):
                update_config_section(
                    str(config_path),
                    "admin_auth",
                    {"password_change_required": True},
                )

            saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
            self.assertTrue(saved["admin_auth"]["password_change_required"])
            self.assertEqual(list(Path(directory).iterdir()), [config_path])

    def test_example_config_keeps_read_api_authentication_opt_in(self):
        example_config = Path(__file__).resolve().parents[1] / "config.example.yaml"
        self.assertFalse(load_config(str(example_config)).read_api_auth_required)

    def test_probe_alerts_are_deduplicated_and_recovery_is_recorded(self):
        cfg = SimpleNamespace(
            alert_enabled=True,
            alert_webhook_url=None,
            alert_latency_ms=250,
            alert_jitter_ms=50,
            alert_loss_pct=2,
            alert_path_change=True,
        )
        target = TargetConfig(host="monitor.example", label="Monitor")

        first_failure = self.add_run(success=False, error="DNS unavailable")
        _evaluate_alerts(self.session, cfg, target, first_failure)
        self.session.commit()

        repeated_failure = self.add_run(success=False, error="DNS unavailable")
        _evaluate_alerts(self.session, cfg, target, repeated_failure)
        self.session.commit()

        recovered = self.add_run(success=True)
        _evaluate_alerts(self.session, cfg, target, recovered)
        self.session.commit()

        kinds = [
            event.kind
            for event in self.session.query(AlertEvent).order_by(AlertEvent.id.asc()).all()
        ]
        self.assertEqual(kinds, ["probe_failure", "probe_recovery"])


if __name__ == "__main__":
    unittest.main()
