from io import BytesIO
import unittest
import datetime
import json
from flask_bcrypt import Bcrypt
from flask_testing import TestCase
from app import app, db
from app import models
from app.models import *
from flask import url_for
from datetime import timedelta


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
    
    ####   ERASE ONCE COMPLETED    ###
    def test_wronglogin(self):
        """Test invalid user login."""
        # Register a user
        response = self.client.post('/login', data=dict(
            username='testuser',
            password='Wrongpassword!'), follow_redirects=True)
    
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b'Incorrect username or password. Please try again.', response.data)
        
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
        

class TestFileUpload(TestCase):

    def create_app(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
        return app

    def setUp(self):
        db.create_all()
        self.client = app.test_client()

        # Create and login a test user
        hashed_password = bcrypt.generate_password_hash("Testpassword!")
        test_user = User(username='testuser', firstname='t', lastname='t', email='t@t.com', password=hashed_password)
        db.session.add(test_user)
        db.session.commit()

        # Login
        self.client.post('/login', data=dict(
            username='testuser',
            password='Testpassword!'
        ), follow_redirects=True)

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def test_file_upload(self):
        """Test file upload functionality."""
        with self.client:
            # Log in the test user
            self.client.post('/login', data=dict(
                username='testuser',
                password='Testpassword!'
            ), follow_redirects=True)

            # Perform file upload
            test_user = User.query.filter_by(username='testuser').first()  # Define the test_user variable
            response = self.client.post('/upload', data=dict(
                file=(BytesIO(b"some initial gpx data"), 'test.gpx'),
            ), content_type='multipart/form-data', follow_redirects=True)

            self.assertEqual(response.status_code, 200)
            self.assertIn(b'File successfully uploaded', response.data)

            # Check if the file is now in the database
            file = models.GPXFile.query.filter_by(user_id=test_user.id).first()
            self.assertIsNotNone(file)

class TestFileDownload(TestCase):
    
    def create_app(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
        return app

    def setUp(self):
        db.create_all()
        self.client = app.test_client()

        # Create and login a test user
        hashed_password = bcrypt.generate_password_hash("Testpassword!")
        test_user = User(username='testuser', firstname='t', lastname='t', email='t@t.com', password=hashed_password)
        db.session.add(test_user)
        db.session.commit()

        # Login
        self.client.post('/login', data=dict(
            username='testuser',
            password='Testpassword!'
        ), follow_redirects=True)

        # Perform file upload
        self.client.post('/upload', data=dict(
                file=(BytesIO(b"some initial gpx data"), 'test.gpx'),
            ), content_type='multipart/form-data', follow_redirects=True)

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def test_file_download(self):
        """Test file download functionality."""
        # Assume a file has been uploaded, either in setUp or another test
        with self.client:
            # Log in the test user
            self.client.post('/login', data=dict(
                username='testuser',
                password='Testpassword!'
            ), follow_redirects=True)

            # get the filename by getting all user's files
            file = models.GPXFile.query.filter_by(user_id=1).first()
            filename = file.filename

            # Attempt to download the file
            response = self.client.get(f'/download/{filename}', follow_redirects=True)
            self.assertEqual(response.status_code, 200)
            self.assertTrue(b"some initial gpx data" in response.data)

class TestUserHasPaid(TestCase):

    def create_app(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
        return app

    def setUp(self):
        db.create_all()
        self.client = app.test_client()
        self.browser = None
        self.page = None

        # Generate new user. Does not log in (logs in during tests)
        # Leave the password as the same (not testing this)
        hashed_password = bcrypt.generate_password_hash("Testpassword!")
        test_user_not_paid = User(username='testusernotpaid', firstname='not', lastname='paid', email='not@paid.com', password=hashed_password, has_paid=False)
        test_user_has_paid = User(username='testuserhaspaid', firstname='has', lastname='paid', email='has@paid.com', password=hashed_password, has_paid=True)
        subscription_details_for_user_has_paid = Subscriptions(user_id=2, subscription_type="Weekly", payment_date=datetime.utcnow() + timedelta(days=7))
        db.session.add(test_user_not_paid)
        db.session.add(test_user_has_paid)
        db.session.add(subscription_details_for_user_has_paid)
        db.session.commit()
        
    def tearDown(self):
        db.session.remove()
        db.drop_all()
        
    # Test case for when the user wants to log in after cancelling subscription
    def test_login_after_cancelling_subscription(self):
        
        # Log in as the test user who hasnt paid
        response = self.client.post('/login', data=dict(
            username='testusernotpaid',
            password='Testpassword!',
            submit='Submit'
        ), follow_redirects=False)

        # Check if redirected to select_payment page by checking the contents of the redirected webpage
        self.assertRedirects(response, '/select_payment')

    def test_correct_password_check_to_cancel_subscription(self):

        with self.client as c:
            # Login as test user who has paid
            username = "testuserhaspaid"
            c.post('/login', data=dict(
                username=username,
                password='Testpassword!',
                submit='Submit'), follow_redirects=True)
            
            #
            c.get('/cancel_subscription')
            response = c.post('/cancel_subscription', data=dict(
                password='Testpassword!',
                submit='Submit'), follow_redirects=False)
            
            user = models.User.query.filter_by(username=username).first()

            self.assertEqual(user.has_paid, False)
            self.assertRedirects(response, '/logout')

    def test_wrong_password_check_to_cancel_subscription(self):

        with self.client as c:
            username = "testuserhaspaid"
            c.post('/login', data=dict(
                username=username,
                password='Testpassword!',
                submit='Submit'), follow_redirects=True)

            c.get('/cancel_subscription')
            response = c.post('/cancel_subscription', data=dict(
                password='WrongPassword!',
                submit='Submit'), follow_redirects=False)
            
            user = models.User.query.filter_by(username=username).first()

            self.assertEqual(user.has_paid, True)
            self.assertRedirects(response, '/cancel_subscription')

        
class TestUserHasNotLoggedIn(TestCase):

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

    def testing_redirects_to_login_if_user_has_no_details(self):

        # This is a blacklist for URL's to not test when looking at login redirects
        # Add stuff here if you think the URL does not need the @login_required decorator
        login_redirects_not_to_test = ["/login_new_user", "/register", "/login", "/static/bootstrap/<path:filename>", "/static/<path:filename>"]

        with self.client as c:
            # Looking across all URL's
            for rule in app.url_map.iter_rules():
                # Ignoring blacklisted URL's
                if rule.rule not in login_redirects_not_to_test:
                    
                    response = c.get(rule.rule)
                    # Check if the redirect location is the login page
                    expected_redirect_location = url_for('login', _external=True)
                    url = response.headers['Location']

                    if '?' in url:
                        # Split the URL at the question mark
                        url_parts = url.split('?')

                        # Extract the part before the question mark
                        url_before_question_mark = url_parts[0]
                    else:
                        # If there is no question mark, use the URL as it is
                        url_before_question_mark = url

                    self.assertTrue(response.status_code in [301, 302, 303, 305, 307])
                    self.assertEqual(url_before_question_mark, expected_redirect_location)



if __name__ == "__main__":
    unittest.main()

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
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestFileUpload))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestFileDownload))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestUserHasPaid))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestUserHasNotLoggedIn))
    unittest.TextTestRunner(resultclass=CustomTestResult).run(suite)