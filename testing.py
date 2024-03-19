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
        test_user = User(username='testuser', firstname='t',
                         lastname='t', email='t@t.com', password=hashed_password)
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
        test_user = User(username='testuser', firstname='t',
                         lastname='t', email='t@t.com', password=hashed_password)
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
        test_user = User(username='testuser', firstname='t',
                         lastname='t', email='t@t.com', password=hashed_password)
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
        test_user = User(username='testuser', firstname='t', lastname='t',
                         email='example@example.com', password=hashed_password)
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
        test_user = User(username='testuser', firstname='t', lastname='t',
                         email='example@example.com', password=hashed_password)
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
        user1 = User(username='john_doe', firstname='John', lastname='Doe', email='john@example.com',
                     password=bcrypt.generate_password_hash('test').decode('utf-8'))
        user2 = User(username='jane_doe', firstname='Jane', lastname='Doe', email='jane@example.com',
                     password=bcrypt.generate_password_hash('test').decode('utf-8'))
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
        self.assertIn(b'jane_doe', response.data,
                      "Search did not return expected results")


class TestFriendRequest(unittest.TestCase):

    def create_app(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        return app

    def setUp(self):
        self.app = self.create_app()
        self.client = self.app.test_client()
        db.create_all()

        # Create test users
        bcrypt = Bcrypt(self.app)
        hashed_password1 = bcrypt.generate_password_hash(
            "password1").decode('utf-8')
        hashed_password2 = bcrypt.generate_password_hash(
            "password2").decode('utf-8')
        user1 = User(username='user1', password=hashed_password1,
                     firstname='User', lastname='One', email='user1@example.com')
        user2 = User(username='user2', password=hashed_password2,
                     firstname='User', lastname='Two', email='user2@example.com')
        db.session.add(user1)
        db.session.add(user2)
        db.session.commit()

        # Login as user1 to send friend requests
        self.client.post(
            '/login', data=dict(username='user1', password='password1'))

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def test_send_friend_request(self):
        # Test sending a friend request
        response = self.client.post('/send_friend_request/user2')
        self.assertEqual(response.status_code, 302)

        # Verify the friend request is in the database
        friend_request = FriendRequest.query.filter_by(
            sender_id=1, receiver_id=2).first()
        self.assertIsNotNone(friend_request)
        self.assertEqual(friend_request.status, 'pending')

    def test_accept_friend_request(self):
        # Assuming we have a friend request from user1 to user2
        self.test_send_friend_request()

        # Logout user1 and login as user2 to accept the request
        self.client.get('/logout')
        self.client.post(
            '/login', data=dict(username='user2', password='password2'))

        # Accept the friend request
        request_id = FriendRequest.query.filter_by(
            sender_id=1, receiver_id=2).first().id
        response = self.client.post(f'/accept_friend_request/{request_id}')
        self.assertEqual(response.status_code, 302)

        # Verify the friend request status is now 'accepted'
        friend_request = FriendRequest.query.get(request_id)
        self.assertEqual(friend_request.status, 'accepted')

    def test_deny_friend_request(self):
        # First, send a friend request from user1 to user2
        self.test_send_friend_request()

        # Logout user1 and login as user2 to deny the request
        self.client.get('/logout')
        self.client.post(
            '/login', data=dict(username='user2', password='password2'))

        # Deny the friend request
        request_id = FriendRequest.query.filter_by(
            sender_id=1, receiver_id=2).first().id
        response = self.client.post(f'/deny_friend_request/{request_id}')
        # assuming redirect on success
        self.assertEqual(response.status_code, 302)

        # Verify the friend request has been removed from the database
        denied_request = FriendRequest.query.get(request_id)
        self.assertIsNone(
            denied_request, "The friend request should be deleted after denial")

    def test_cancel_friend_request(self):
        # Send a friend request from user1 to user2
        self.test_send_friend_request()

        # Cancel the friend request
        request_id = FriendRequest.query.filter_by(
            sender_id=1, receiver_id=2).first().id
        response = self.client.post(f'/cancel_friend_request/{request_id}')
        # assuming redirect on success
        self.assertEqual(response.status_code, 302)

        # Verify the friend request has been removed from the database
        canceled_request = FriendRequest.query.get(request_id)
        self.assertIsNone(
            canceled_request, "The friend request should be deleted after cancellation")


class CreateGroup(unittest.TestCase):

    def create_app(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        return app

    def setUp(self):
        self.app = self.create_app()
        self.client = self.app.test_client()
        db.create_all()

        # Create test users
        user1 = User(username='user1', firstname='User', lastname='One', email='user1@example.com',
                     password=bcrypt.generate_password_hash('password1').decode('utf-8'))
        user2 = User(username='user2', firstname='User', lastname='Two', email='user2@example.com',
                     password=bcrypt.generate_password_hash('password2').decode('utf-8'))
        db.session.add(user1)
        db.session.add(user2)
        db.session.commit()

        self.client.post(
            '/login', data=dict(username='user1', password='password1'))

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def send_friend_request(self):
        # Test sending a friend request
        response = self.client.post('/send_friend_request/user2')
        self.assertEqual(response.status_code, 302)

        # Verify the friend request is in the database
        friend_request = FriendRequest.query.filter_by(
            sender_id=1, receiver_id=2).first()
        self.assertIsNotNone(friend_request)
        self.assertEqual(friend_request.status, 'pending')

    def accept_friend_request(self):
        # Assuming we have a friend request from user1 to user2
        self.send_friend_request()

        # Logout user1 and login as user2 to accept the request
        self.client.get('/logout')
        self.client.post(
            '/login', data=dict(username='user2', password='password2'))

        # Accept the friend request
        request_id = FriendRequest.query.filter_by(
            sender_id=1, receiver_id=2).first().id
        response = self.client.post(f'/accept_friend_request/{request_id}')
        self.assertEqual(response.status_code, 302)

        # Verify the friend request status is now 'accepted'
        friend_request = FriendRequest.query.get(request_id)
        self.assertEqual(friend_request.status, 'accepted')

    def test_create_group_with_friend(self):
        self.accept_friend_request()

        user2 = User.query.filter_by(email='user2@example.com').first()

    # Ensure you're logged in as user1 and then create the group
        self.client.post(
            '/login', data=dict(username='user1', password='password1'))
        self.client.post('/group', data={
            'group_name': 'Besties',
            'selected_friends': [str(user2.id)]
        })

        new_group = Group.query.filter_by(name='Besties').first()
        self.assertIsNotNone(new_group, "Group was not created")

    # Retrieve group members
        group_members = GroupMember.query.filter_by(
            group_id=new_group.id).all()
        self.assertTrue(any(member.user_id == user2.id for member in group_members),
                        "User2 is not a member of the new group")


class GroupTestCase(unittest.TestCase):
    def create_app(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        return app

    def setUp(self):
        self.app = self.create_app()
        self.client = self.app.test_client()
        db.create_all()

        # Create test users
        for i in range(1, 5):
            user = User(username=f'user{i}', firstname='test', lastname='user',
                        email=f'user{i}@example.com', password=bcrypt.generate_password_hash(f'password{i}'))
            db.session.add(user)
        db.session.commit()

        # Establish friendships
        self.establish_friendships()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def login(self, username, password):
        return self.client.post('/login', data={'username': username, 'password': password}, follow_redirects=True)

    def logout(self):
        return self.client.get('/logout', follow_redirects=True)

    def establish_friendships(self):
        users = User.query.all()
        for user in users:
            for friend in users:
                if user.id != friend.id:
                    # Check if the friendship (accepted request) already exists to avoid duplicates
                    existing_request = FriendRequest.query.filter(
                        ((FriendRequest.sender_id == user.id) & (FriendRequest.receiver_id == friend.id)) |
                        ((FriendRequest.receiver_id == user.id) &
                         (FriendRequest.sender_id == friend.id))
                    ).first()

                    if not existing_request:
                        # Directly create an accepted friend request between the users
                        new_request = FriendRequest(
                            sender_id=user.id, receiver_id=friend.id, status='accepted')
                        db.session.add(new_request)
        db.session.commit()

    def test_group_creation(self):
        # Login as user1
        self.login('user1', 'password1')

        # Users 1 and 2 create a group named "group1"
        response = self.client.post(
            '/group', data={'group_name': 'group1', 'selected_friends': '2'}, follow_redirects=True)
        self.assertIn(b'Group created successfully.', response.data)

        # Attempt by user3 to create a group named "group1" with user2 should fail
        self.logout()
        self.login('user3', 'password3')
        response = self.client.post(
            '/group', data={'group_name': 'group1', 'selected_friends': '2'}, follow_redirects=True)
        self.assertIn(b'A group with this name already exists', response.data)

        # User3 creates a group named "group1" with user4, which should succeed
        response = self.client.post(
            '/group', data={'group_name': 'group1', 'selected_friends': '4'}, follow_redirects=True)
        self.assertIn(b'Group created successfully.', response.data)


if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(TestRegistration)
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestLogin))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestWrongLogin))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestLogout))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestEmailInUse))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestNameInUse))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(
        TestNoSpecialCharPassword))
    suite.addTests(unittest.TestLoader(
    ).loadTestsFromTestCase(TestNoCapsPassword))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(
        TestInvalidLengthPassword))
    suite.addTests(unittest.TestLoader(
    ).loadTestsFromTestCase(TestPasswordsMismatch))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestUserSearch))
    suite.addTests(unittest.TestLoader(
    ).loadTestsFromTestCase(TestFriendRequest))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(CreateGroup))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(GroupTestCase))

    unittest.TextTestRunner(resultclass=CustomTestResult).run(suite)
