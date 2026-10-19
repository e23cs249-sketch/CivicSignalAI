import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app
from app.services.team_auth import provision_team_user


class CitizenAuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.environment = patch.dict(os.environ, {
            "CIVICSIGNAL_DATABASE_PATH": str(Path(self.temp.name) / "civicsignal.db")
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.client_context = TestClient(app, raise_server_exceptions=False)
        self.client = self.client_context.__enter__()
        self.addCleanup(self.client_context.__exit__, None, None, None)
        self.email = "citizen@example.test"
        self.password = "valid-citizen-password"

    def signup(self, email=None):
        return self.client.post("/api/auth/citizen/register", json={
            "full_name": "Test Citizen",
            "email": email or self.email,
            "phone": "5551234567",
            "password": self.password,
            "confirm_password": self.password,
            "accepted_terms": True,
        })

    def create_report(self):
        return self.client.post("/api/reports", json={
            "description": "The streetlight is out near the library.",
            "category": "broken_streetlight",
            "landmark": "Near the library",
        })

    def test_unauthenticated_visitors_are_gated_from_citizen_pages_and_apis(self):
        anonymous = TestClient(app, follow_redirects=False)
        root = anonymous.get("/")
        self.assertEqual(root.status_code, 200)
        self.assertIn("citizen-login-form", root.text)
        for path in ("/home", "/report", "/report.html", "/tracking.html", "/static/index.html", "/static/report.html"):
            with self.subTest(path=path):
                self.assertEqual(anonymous.get(path).status_code, 303)

        self.assertEqual(anonymous.post("/api/reports/preview", json={
            "description": "Streetlight is out",
            "category": "broken_streetlight",
        }).status_code, 401)
        self.assertEqual(anonymous.post("/api/reports", json={
            "description": "Streetlight is out",
            "category": "broken_streetlight",
        }).status_code, 401)
        self.assertEqual(anonymous.get("/api/reports/not-a-report/tracking").status_code, 401)
        self.assertEqual(anonymous.get("/api/reports").status_code, 401)
        self.assertEqual(anonymous.get("/team", follow_redirects=False).status_code, 303)

    def test_registration_login_logout_and_session_persistence(self):
        registration = self.signup()
        self.assertEqual(registration.status_code, 200, registration.text)
        cookie = registration.headers["set-cookie"].lower()
        self.assertIn("httponly", cookie)
        self.assertIn("samesite=strict", cookie)
        self.assertEqual(self.client.get("/api/auth/citizen/me").status_code, 200)
        self.assertEqual(self.client.get("/home").status_code, 200)
        self.assertEqual(self.client.get("/report").status_code, 200)
        self.assertEqual(self.client.get("/report.html").status_code, 200)
        self.assertEqual(self.client.get("/tracking.html").status_code, 200)
        self.assertEqual(self.client.get("/team", follow_redirects=False).status_code, 303)

        duplicate = self.signup()
        self.assertEqual(duplicate.status_code, 409)
        logout = self.client.post("/api/auth/citizen/logout")
        self.assertEqual(logout.status_code, 200)
        self.assertEqual(self.client.get("/api/auth/citizen/me").status_code, 401)
        self.assertEqual(self.client.get("/home", follow_redirects=False).status_code, 303)

        invalid_login = self.client.post("/api/auth/citizen/login", json={
            "email": self.email,
            "password": "incorrect-password",
        })
        self.assertEqual(invalid_login.status_code, 401)
        login = self.client.post("/api/auth/citizen/login", json={
            "email": self.email,
            "password": self.password,
        })
        self.assertEqual(login.status_code, 200, login.text)
        self.assertEqual(self.client.get("/home").status_code, 200)

    def test_registration_checks_terms_password_match_and_profile_fields(self):
        payload = {
            "full_name": "Test Citizen",
            "email": self.email,
            "phone": "5551234567",
            "password": self.password,
            "confirm_password": "another-valid-password",
            "accepted_terms": False,
        }
        terms = self.client.post("/api/auth/citizen/register", json=payload)
        self.assertEqual(terms.status_code, 400)
        payload["accepted_terms"] = True
        mismatch = self.client.post("/api/auth/citizen/register", json=payload)
        self.assertEqual(mismatch.status_code, 400)
        payload["confirm_password"] = self.password
        payload["full_name"] = "  "
        blank_name = self.client.post("/api/auth/citizen/register", json=payload)
        self.assertEqual(blank_name.status_code, 422)

    def test_reports_are_private_to_their_citizen_and_admins_can_still_view_them(self):
        self.assertEqual(self.signup().status_code, 200)
        created = self.create_report()
        self.assertEqual(created.status_code, 201, created.text)
        report_id = created.json()["id"]
        own_tracking = self.client.get(f"/api/reports/{report_id}/tracking")
        self.assertEqual(own_tracking.status_code, 200)

        self.client.post("/api/auth/citizen/logout")
        self.assertEqual(self.signup("other@example.test").status_code, 200)
        other_tracking = self.client.get(f"/api/reports/{report_id}/tracking")
        self.assertEqual(other_tracking.status_code, 404)
        forbidden_update = self.client.patch(
            f"/api/team/reports/{report_id}/status",
            json={"status": "acknowledged"},
        )
        self.assertEqual(forbidden_update.status_code, 401)

        provision_team_user("admin@city.test", "a-valid-admin-password")
        admin_login = self.client.post("/api/auth/team/login", json={
            "email": "admin@city.test",
            "password": "a-valid-admin-password",
        })
        self.assertEqual(admin_login.status_code, 200)
        self.assertEqual(self.client.get(f"/api/reports/{report_id}/tracking").status_code, 200)
        self.assertEqual(self.client.get("/api/reports").status_code, 200)
