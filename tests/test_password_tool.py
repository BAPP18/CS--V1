import unittest

from modules.password_tool import generate_password


class PasswordToolTests(unittest.TestCase):
    def test_generated_password_length(self):
        password = generate_password(24)
        self.assertEqual(len(password), 24)

    def test_generated_passwords_are_not_reused(self):
        self.assertNotEqual(generate_password(24), generate_password(24))


if __name__ == "__main__":
    unittest.main()
