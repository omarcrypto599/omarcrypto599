import html
import os
import tempfile
import unittest

from app import app, initialize_database


class WebSecurityLabTests(unittest.TestCase):
    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(delete=False)
        self.temp_db.close()
        app.config["DATABASE"] = self.temp_db.name
        app.config["TESTING"] = True
        initialize_database()
        self.client = app.test_client()

    def tearDown(self):
        os.unlink(self.temp_db.name)

    def test_home_page_loads(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Web Security Testing Lab", response.data)

    def test_safe_sql_query_returns_matching_user(self):
        response = self.client.post("/sql-injection", data={"term": "alice"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"alice", response.data)
        self.assertIn(b"Safe parameterized query", response.data)

    def test_safe_sql_query_treats_input_as_data(self):
        response = self.client.post("/sql-injection", data={"term": "' OR '1'='1"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Safe parameterized query", response.data)
        self.assertIn(b"No matching records.", response.data)

    def test_safe_xss_output_is_escaped(self):
        response = self.client.post("/xss", data={"message": "<b>hello</b>"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(html.escape("<b>hello</b>").encode(), response.data)
        self.assertIn(b"Safe escaped output", response.data)

    def test_security_headers_are_present(self):
        response = self.client.get("/")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])


if __name__ == "__main__":
    unittest.main()
