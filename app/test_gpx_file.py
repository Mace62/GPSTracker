import unittest
from unittest.mock import mock_open, patch
from models import GPXFile, GPXTrack, GPXPoint
import datetime

class TestGPXPoint(unittest.TestCase):
    def test_display_info(self):
        point = GPXPoint("Point1", 10.0, 20.0, 30.0, datetime.datetime.now())
        with patch('builtins.print') as mocked_print:
            point.display_info()
            self.assertTrue(mocked_print.called)

class TestGPXTrack(unittest.TestCase):
    def test_display_info(self):
        track = GPXTrack("Track1")
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

        gpx_file = GPXFile("TestFile", "C:/Users/rashi/Downloads/fells_loop.gpx")

        self.assertEqual(gpx_file.name, "TestFile")
        self.assertTrue(len(gpx_file.waypoints) > 0)
        self.assertEqual(gpx_file.waypoints[0].name, "Point1")

    def test_display_info(self):
        gpx_file = GPXFile("TestFile", "C:/Users/rashi/Downloads/fells_loop.gpx")
        gpx_file.tracks.append(GPXTrack("Track1"))
        gpx_file.waypoints.append(GPXPoint("Point1", 10.0, 20.0, 30.0, datetime.datetime.now()))
        with patch('builtins.print') as mocked_print:
            gpx_file.display_info()
            self.assertTrue(mocked_print.called)

if __name__ == '__main__':
    unittest.main()
