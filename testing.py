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
            password='Testpassword!',
            confirm='Testpassword!',
            email='example@example.com',
            first_name='Test',
            last_name='User'
        ), follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b'Registered and logged in successfully.', response.data)

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
        hashed_password = bcrypt.generate_password_hash("Testpassword!")
        test_user = User(username='testuser', firstname='t', lastname='t', email='t@t.com',password=hashed_password)
        db.session.add(test_user)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def test_login(self):
        """Test user login."""
        # Register a user
        response = self.client.post('/login', data=dict(
            username='testuser',
            password='Testpassword!'), follow_redirects=True)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b'Logged in successfully.', response.data)
        
class TestWrongLogin(TestCase):

    def create_app(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
        return app

    def setUp(self):
        db.create_all()
        self.client = app.test_client()

        # Create a test user for login
        hashed_password = bcrypt.generate_password_hash("Testpassword!")
        test_user = User(username='testuser', firstname='t', lastname='t', email='t@t.com',password=hashed_password)
        db.session.add(test_user)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def test_wronglogin(self):
        """Test invalid user login."""
        # Register a user
        response = self.client.post('/login', data=dict(
            username='testuser',
            password='Wrongpassword!'), follow_redirects=True)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b'Incorrect username or password. Please try again.', response.data)


class TestLogout(TestCase):

    def create_app(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
        return app

    def setUp(self):
        db.create_all()
        self.client = app.test_client()
        # Create a test user for login
        hashed_password = bcrypt.generate_password_hash("Testpassword!")
        test_user = User(username='testuser', firstname='t', lastname='t', email='t@t.com',password=hashed_password)
        db.session.add(test_user)
        db.session.commit()

        # Log in the test user
        response = self.client.post('/login', data=dict(
            username='testuser',
            password='Testpassword!'
        ), follow_redirects=True)

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def test_logout(self):
        """Test user logout."""
        response = self.client.get('/logout', follow_redirects=True)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b'You have been logged out.', response.data)
        
class TestEmailInUse(TestCase):

    def create_app(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
        return app

    def setUp(self):
        db.create_all()
        self.client = app.test_client()

        # create a user
        hashed_password = bcrypt.generate_password_hash("Testpassword!")
        test_user = User(username='testuser', firstname='t', lastname='t', email='example@example.com',password=hashed_password)
        db.session.add(test_user)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def test_email_in_use(self):
        """Test invalid registration via already-in-use email."""

        # create another user with the same email
        response = self.client.post('/register', data=dict(
            username='testuser1',
            password='Testpassword!',
            confirm='Testpassword!',
            email='example@example.com',
            first_name='Test',
            last_name='User'
        ), follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b'Email exists, try a different email.', response.data)
        
class TestNameInUse(TestCase):

    def create_app(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
        return app

    def setUp(self):
        db.create_all()
        self.client = app.test_client()

        # create a user
        hashed_password = bcrypt.generate_password_hash("Testpassword!")
        test_user = User(username='testuser', firstname='t', lastname='t', email='example@example.com',password=hashed_password)
        db.session.add(test_user)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def test_name_in_use(self):
        """Test invalid registration via already-in-use username."""

        # create another user with the same username
        response = self.client.post('/register', data=dict(
            username='testuser',
            password='Testpassword!',
            confirm='Testpassword!',
            email='example1@example.com',
            first_name='Test',
            last_name='User'
        ), follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b'Username exists, try a different name.', response.data)

class TestNoSpecialCharPassword(TestCase):

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

    def test_no_special_char(self):
        """Test invalid registration via poor password (no special character)."""

        # create a user with a password that has no special characters
        response = self.client.post('/register', data=dict(
            username='testuser',
            password='Password',
            confirm='Password',
            email='example1@example.com',
            first_name='Test',
            last_name='User'
        ), follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b'Password must contain at least one special character.', response.data)   

class TestNoCapsPassword(TestCase):

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

    def test_no_caps(self):
        """Test invalid registration via poor password (no capital letter)."""

        # create a user with a password that has no capital letters
        response = self.client.post('/register', data=dict(
            username='testuser',
            password='password!',
            confirm='password!',
            email='example1@example.com',
            first_name='Test',
            last_name='User'
        ), follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b'Password must contain at least one capital letter.', response.data)
        
class TestInvalidLengthPassword(TestCase):

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

    def test_invalid_length(self):
        """Test invalid registration via poor password (not at least 8 characters)."""

        # create a user with a password that is too short
        response = self.client.post('/register', data=dict(
            username='testuser',
            password='Passwo!',
            confirm='Passwo!',
            email='example1@example.com',
            first_name='Test',
            last_name='User'
        ), follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b'Password must be at least 8 characters long.', response.data)
        
class TestPasswordsMismatch(TestCase):

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

    def test_password_mismatch(self):
        """Test invalid registration via poor password (Passwords don't match)."""

        # create a user with mismatching passwords
        response = self.client.post('/register', data=dict(
            username='testuser',
            password='Password!',
            confirm='Passsword!',
            email='example1@example.com',
            first_name='Test',
            last_name='User'
        ), follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b'Passwords do not match.', response.data)

class TestUserSearch(TestCase):

    def create_app(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
        return app

    def setUp(self):
        # Set up the database and test client, and add test data
        db.create_all()
        self.client = app.test_client()
        # Add a couple of users to search
        user1 = User(username='john_doe', firstname='John', lastname='Doe', email='john@example.com', password=bcrypt.generate_password_hash('test').decode('utf-8'))
        user2 = User(username='jane_doe', firstname='Jane', lastname='Doe', email='jane@example.com', password=bcrypt.generate_password_hash('test').decode('utf-8'))
        db.session.add_all([user1, user2])
        db.session.commit()

    def tearDown(self):
        # Tear down and clean up the database
        db.session.remove()
        db.drop_all()

    def test_user_search(self):
        """Test searching for a user by username."""
        login_response = self.client.post('/login', data=dict(
            username='john_doe',
            password='test'), follow_redirects=True)
        self.assertEqual(login_response.status_code, 200, "Login failed")

        response = self.client.get('/profile?q=jane', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        # Check if the search results contain the expected username
        self.assertIn(b'jane_doe', response.data, "Search did not return expected results")
        
class TestAddFriends(TestCase):

    def create_app(self):
        # Setup Flask application configuration for testing
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
        return app

    def setUp(self):
        # Initialize the database and test client, and create test users
        db.create_all()
        self.client = app.test_client()
      # Add a couple of users to add
        user1 = User(username='john_doe', firstname='John', lastname='Doe', email='john@example.com', password=bcrypt.generate_password_hash('test').decode('utf-8'))
        user2 = User(username='jane_doe', firstname='Jane', lastname='Doe', email='jane@example.com', password=bcrypt.generate_password_hash('test').decode('utf-8'))
        db.session.add_all([user1, user2])
        db.session.commit()

    def tearDown(self):
        # Clean up the database after tests
        db.session.remove()
        db.drop_all()

    def login(self, username, password):
        # Helper method to log in a user
        return self.client.post('/login', data={
            'username': username,
            'password': password
        }, follow_redirects=True)

    def logout(self):
        # Helper method to log out the current user
        return self.client.get('/logout', follow_redirects=True)

    def test_accept_friend_request(self):
        """Ensure that a user can accept a friend request."""
        # User1 logs in and sends a friend request to User2
        self.login('user1', 'User1password!')
        user2 = User.query.filter_by(username='user2').first()
        self.client.post(f'/send_friend_request/{user2.username}', follow_redirects=True)
        self.logout()

        # User2 logs in to accept the friend request from User1
        self.login('user2', 'User2password!')
        friend_request = FriendRequest.query.filter_by(sender_id=User.query.filter_by(username='user1').first().id, receiver_id=user2.id).first()
        accept_response = self.client.post(f'/accept_friend_request/{friend_request.id}', follow_redirects=True)
        self.assertIn(b'Friend request accepted.', accept_response.data, "Accepting friend request failed or confirmation message missing")

        # Verify the friend request status has been updated to 'accepted'
        updated_request = FriendRequest.query.get(friend_request.id)
        self.assertEqual(updated_request.status, 'accepted', "Friend request was not correctly accepted")

        self.logout()
if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(TestRegistration)
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestLogin))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestWrongLogin))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestLogout))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestEmailInUse))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestNameInUse))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestNoSpecialCharPassword))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestNoCapsPassword))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestInvalidLengthPassword))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestPasswordsMismatch))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestAddFriends))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestUserSearch))

    
    


    unittest.TextTestRunner(resultclass=CustomTestResult).run(suite)