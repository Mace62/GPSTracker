import unittest
import datetime
import json
from flask_bcrypt import Bcrypt
from flask_testing import TestCase
from app import app, db
from app.models import *

bcrypt = Bcrypt(app)

# use
# SQLALCHEMY_WARN_20=1 SQLALCHEMY_SILENCE_UBER_WARNING=1 python test_app.py
# in terminal, if too messy


class CustomTestResult(unittest.TextTestResult):
    def startTest(self, test):
        super().startTest(test)
        print(f"Running test: {test.id()} - {test.shortDescription()}")

    def addSuccess(self, test):
        super().addSuccess(test)
        print(f"  -> Passed")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        print(f"  -> Failed: {err[1]}")

    def addError(self, test, err):
        super().addError(test, err)
        print(f"  -> Error: {err[1]}")

class TestRegistration(TestCase):

    def create_app(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
        return app

    def setUp(self):
        db.create_all()
        self.client = app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def test_registration(self):
        """Test user registration."""
        response = self.client.post('/register', data=dict(
            username='testuser',
            password='testpassword',
            confirm_password='testpassword'
        ), follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b'Your account has been created! You can now log in.', response.data)

        # Check if the user is now in the database
        user = User.query.filter_by(username='testuser').first()
        self.assertIsNotNone(user)
        self.assertEqual(user.username, 'testuser')


class TestLogin(TestCase):

    def create_app(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
        return app

    def setUp(self):
        db.create_all()
        self.client = app.test_client()

        # Create a test user for login
        hashed_password = bcrypt.generate_password_hash("testpassword")
        test_user = User(username='testuser', password=hashed_password)
        db.session.add(test_user)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def test_login(self):
        """Test user login."""
        response = self.client.post('/login', data=dict(
            username='testuser',
            password='testpassword'
        ), follow_redirects=True)

        self.assertEqual(response.status_code, 200)

        decoded_response = response.data.decode('utf-8')
        self.assertIn('Hello there', decoded_response)


class TestIncorrectLogin(TestCase):

    def create_app(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
        return app

    def setUp(self):
        db.create_all()
        self.client = app.test_client()

        # Create a test user for login
        hashed_password = bcrypt.generate_password_hash("testpassword")
        test_user = User(username='testuser', password=hashed_password)
        db.session.add(test_user)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def test_login(self):
        """Test incorrect user login."""
        response = self.client.post('/login', data=dict(
            username='testuser',
            password='testpassword1'
        ), follow_redirects=True)

        self.assertEqual(response.status_code, 200)

        decoded_response = response.data.decode('utf-8')
        self.assertIn(
            'Incorrect username or password. Please try again.', decoded_response)


class TestLogout(TestCase):

    def create_app(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
        return app

    def setUp(self):
        db.create_all()
        self.client = app.test_client()

        # Create a test user
        hashed_password = bcrypt.generate_password_hash("testpassword")
        test_user = User(username='testuser', password=hashed_password)
        db.session.add(test_user)
        db.session.commit()

        # Log in the test user
        response = self.client.post('/login', data=dict(
            username='testuser',
            password='testpassword'
        ), follow_redirects=True)

        self.assertEqual(response.status_code, 200)

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def test_logout(self):
        """Test user logout."""
        # Log out the user
        response = self.client.get('/logout', follow_redirects=True)
        self.assertEqual(response.status_code, 200)

        # Check if the user is no longer authenticated
        with self.client as c:
            response = c.get('/profile', follow_redirects=True)
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'Login Page', response.data)


if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(TestRegistration)
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestLogin))
    suite.addTests(unittest.TestLoader(
    ).loadTestsFromTestCase(TestIncorrectLogin))
    unittest.TextTestRunner(resultclass=CustomTestResult).run(suite)