from flask_login import UserMixin
from app import db
from datetime import datetime

import gpxpy
import gpxpy.gpx

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(64), index = True, unique = True, nullable = False)
    firstname = db.Column(db.String(120), index = True, nullable = False)
    lastname = db.Column(db.String(120), index = True, nullable = False)
    email = db.Column(db.String(120), index = True, unique = True, nullable = False)
    password = db.Column(db.String(120), index = True, nullable = False)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class GPXFileData(db.Model):
    __tablename__ = 'gpxfiledata'
    id = db.Column(db.Integer, primary_key = True)
    filename = db.Column(db.String(120), index = True, nullable = False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    upload_time = db.Column(db.DateTime, index = True, default = datetime.utcnow)

class GPXWaypoint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    elevation = db.Column(db.Float)
    time = db.Column(db.DateTime)
    file_id = db.Column(db.Integer, db.ForeignKey('gpxfiledata.id'))

class GPXTrack(db.Model):
    __tablename__ = 'gpxtrack'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    file_id = db.Column(db.Integer, db.ForeignKey('gpxfiledata.id'))

class GPXTrackPoint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    elevation = db.Column(db.Float)
    time = db.Column(db.DateTime)
    track_id = db.Column(db.Integer, db.ForeignKey('gpxtrack.id'))

## Classes for GPX parsing ##
class GPXFile:
    def __init__(self, name, filepath):
        self.name = name
        self.filepath = filepath
        self.tracks = []
        self.waypoints = []

        # Code for parsing in from file
        try:
            with open(self.filepath, 'r') as gpx_file:
                gpx_data = gpxpy.parse(gpx_file)

            # Parsing waypoints
            if gpx_data.waypoints:
                for waypoint in gpx_data.waypoints:
                    self.waypoints.append(GPXPoint(waypoint.name, waypoint.latitude, waypoint.longitude, waypoint.elevation, waypoint.time))

            # Parsing tracks
            if gpx_data.tracks:
                for track in gpx_data.tracks:
                    track_name = track.name if track.name else "Unnamed Track"
                    gpx_track = GPXTrackData(track_name)
                    for segment in track.segments:
                        for point in segment.points:
                            # Check for point data availability
                            if point.latitude is not None and point.longitude is not None:
                                gpx_track.points.append(GPXPoint(None, point.latitude, point.longitude, point.elevation, point.time))
                    self.tracks.append(gpx_track)

        except Exception as e:
            print(f"Error parsing GPX file: {e}")

    def save_to_db(self, user_id):
        gpxfile_data = GPXFileData(filename=self.name, user_id=user_id)
        db.session.add(gpxfile_data)
        db.session.flush()  # This is important to get the id of gpxfile_data

        for waypoint in self.waypoints:
            db_waypoint = GPXWaypoint(
                name=waypoint.name,
                latitude=waypoint.latitude,
                longitude=waypoint.longitude,
                elevation=waypoint.elevation,
                time=waypoint.time,
                file_id=gpxfile_data.id
            )
            
            db.session.add(db_waypoint)

        for track in self.tracks:
            db_track = GPXTrack(name=track.name, file_id=gpxfile_data.id)
            db.session.add(db_track)
            db.session.flush()  # To get the id of db_track

            for point in track.points:
                db_point = GPXTrackPoint(
                    latitude=point.latitude,
                    longitude=point.longitude,
                    elevation=point.elevation,
                    time=point.time,
                    track_id=db_track.id
                )
                db.session.add(db_point)

        db.session.commit()

    def display_info(self):
        print(f"GPX File: {self.name}")
        for track in self.tracks:
            track.display_info()
        print("Waypoints:")
        for waypoint in self.waypoints:
            waypoint.display_info()

class GPXTrackData:
    def __init__(self, name, file_id=None):  # Add file_id parameter
        self.name = name
        self.file_id = file_id  # Store file_id in an instance variable
        self.points = []

    def display_info(self):
        print(f"  Track: {self.name}")
        print("Points:")
        for point in self.points:
            point.display_info()

class GPXPoint:
    def __init__(self, name, latitude, longitude, elevation, time):
        self.name = name
        self.latitude = latitude
        self.longitude = longitude
        self.elevation = elevation
        self.time = time

    def display_info(self):
        print(f"    Point: {self.name}, Location: ({self.latitude}, {self.longitude}), Elevation: {self.elevation}, Time: {self.time}")