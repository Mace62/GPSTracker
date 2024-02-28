from flask_login import UserMixin
from app import db

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

## Classes for GPX parsing ##

class GPXFile:
    def __init__(self, name):
        self.name = name
        self.tracks = []
        self.waypoints = []

    def display_info(self):
        print(f"GPX File: {self.name}")
        for track in self.tracks:
            track.display_info()
        print("Waypoints:")
        for waypoint in self.waypoints:
            waypoint.display_info()

class GPXTrack:
    def __init__(self, name):
        self.name = name
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