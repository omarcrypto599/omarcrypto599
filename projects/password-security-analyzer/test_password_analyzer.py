import unittest

from password_analyzer import analyze_password, has_sequential_pattern


class PasswordAnalyzerTests(unittest.TestCase):
    def test_common_password_is_weak(self):
        result = analyze_password("password123")
        self.assertEqual(result["rating"], "Weak")
        self.assertEqual(result["score"], 0)

    def test_long_varied_password_scores_higher(self):
        result = analyze_password("Violet!River_92_Moon")
        self.assertGreaterEqual(result["score"], 6)
        self.assertIn(result["rating"], {"Good", "Strong"})

    def test_short_password_gets_length_feedback(self):
        result = analyze_password("Ab1!")
        self.assertTrue(any("12 characters" in item for item in result["feedback"]))

    def test_sequential_patterns_are_detected(self):
        self.assertTrue(has_sequential_pattern("safe-1234-value"))
        self.assertTrue(has_sequential_pattern("zyxw-Example"))
        self.assertFalse(has_sequential_pattern("violet!river92"))

    def test_non_string_input_is_rejected(self):
        with self.assertRaises(TypeError):
            analyze_password(None)


if __name__ == "__main__":
    unittest.main()
