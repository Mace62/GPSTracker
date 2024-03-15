from io import BytesIO
import os
import unittest
import datetime
import json
from unittest.mock import mock_open, patch
from flask_bcrypt import Bcrypt
from flask_testing import TestCase
from app import app, db
from app import models
from app.models import *
import datetime

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
        file = models.GPXFileData.query.filter_by(user_id=1).first() 
        if file is not None:
            os.remove(os.path.join( app.root_path, 'static', 'uploads', str(1) , file.filename))


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
                file=(open(os.path.join( app.root_path, 'static', 'Test_Files', 'fells_loop.gpx'), 'rb'), 'fells_loop.gpx'),
            ), content_type='multipart/form-data', follow_redirects=True)

            self.assertEqual(response.status_code, 200)
            self.assertIn(b'File successfully uploaded', response.data)

            # Check if the file is now in the database
            file = models.GPXFileData.query.filter_by(user_id=test_user.id).first()
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
                file=(open(os.path.join( app.root_path, 'static', 'Test_Files', 'fells_loop.gpx'), 'rb'), 'fells_loop.gpx'),
            ), content_type='multipart/form-data', follow_redirects=True)

    def tearDown(self):
        # test_user = User.query.filter_by(username='testuser').first()
        file = models.GPXFileData.query.filter_by(user_id=1).first() 
        if file is not None:
            os.remove(os.path.join( app.root_path, 'static', 'uploads', str(1) , file.filename))

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
            file = models.GPXFileData.query.filter_by(user_id=1).first()
            filename = file.filename

            # Attempt to download the file
            response = self.client.get(f'/download/{filename}', follow_redirects=True)
            self.assertEqual(response.status_code, 201)

class TestDisplayAllUsers(TestCase):

    def create_app(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test_app.db'
        return app

    def setUp(self):
        db.create_all()
        self.client = app.test_client()

        # Login
        self.client.post('/login', data=dict(
            username='admin',
            password='Admin123!'
        ), follow_redirects=True)

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        
    def test_display_all_users(self):
        """Test display all users functionality."""
        with self.client:
            # Log in the test user
            response = self.client.get('/all_users', follow_redirects=True)
            self.assertEqual(response.status_code, 200)

            # Check if 'All Users' is present in the response data
            self.assertIn(b'All Users', response.data)

class TestFutureRevenue(TestCase):

    def create_app(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test_app.db'
        return app

    def setUp(self):
        db.create_all()
        self.client = app.test_client()

        # Login
        self.client.post('/login', data=dict(
            username='admin',
            password='Admin123!'
        ), follow_redirects=True)

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        
    def test_future_revenue(self):
        """Test future revenue functionality."""
        with self.client:
            # Log in the test user
            response = self.client.get('/future_revenue', follow_redirects=True)
            self.assertEqual(response.status_code, 200)

            # Check if 'All Users' is present in the response data
            self.assertIn(b'Future Revenue', response.data)

class TestGPXPoint(unittest.TestCase):
    def test_display_info(self):
        point = GPXPoint("Point1", 10.0, 20.0, 30.0, datetime.datetime.now())
        with patch('builtins.print') as mocked_print:
            point.display_info()
            self.assertTrue(mocked_print.called)

class TestGPXTrack(unittest.TestCase):
    def test_display_info(self):
        track = GPXTrackData("Track1")
        track.points.append(GPXPoint("Point1", 10.0, 20.0, 30.0, datetime.datetime.now()))
        with patch('builtins.print') as mocked_print:
            track.display_info()
            self.assertTrue(mocked_print.called)

class TestGPXFile(unittest.TestCase):
    @patch('builtins.open', new_callable=mock_open, read_data='Mock GPX data')
    @patch('gpxpy.parse')
    def test_init(self, mock_gpxpy_parse, mock_open):
        mock_gpxpy_parse.return_value.waypoints = [GPXPoint("Point1", 10.0, 20.0, 30.0, datetime.datetime.now())]
        mock_gpxpy_parse.return_value.routes = []

        gpx_file = GPXFile("TestFile", os.path.join(app.root_path, 'static', 'Test_Files', 'fells_loop.gpx'))

        self.assertEqual(gpx_file.name, "TestFile")
        self.assertTrue(len(gpx_file.waypoints) > 0)
        self.assertEqual(gpx_file.waypoints[0].name, "Point1")

    def test_display_info(self):
        gpx_file = GPXFile("TestFile", os.path.join(app.root_path, 'static', 'Test_Files', 'fells_loop.gpx'))
        gpx_file.tracks.append(GPXTrackData("Track1"))
        gpx_file.waypoints.append(GPXPoint("Point1", 10.0, 20.0, 30.0, datetime.datetime.now()))
        with patch('builtins.print') as mocked_print:
            gpx_file.display_info()
            self.assertTrue(mocked_print.called)

if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(TestRegistration)
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestLogin))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestWrongLogin))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestLogout))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestEmailInUse))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestNameInUse))
    # suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestNoSpecialCharPassword))
    # suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestNoCapsPassword))
    # suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestInvalidLengthPassword))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestPasswordsMismatch))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestFileUpload))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestFileDownload))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestDisplayAllUsers))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestFutureRevenue))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestGPXPoint))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestGPXTrack))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestGPXFile))

    unittest.TextTestRunner(resultclass=CustomTestResult).run(suite)