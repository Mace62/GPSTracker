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


## Classes for GPX parsing ##
class GPXFile:
    def __init__(self, name, filepath):
        self.name = name
        self.filepath = filepath
        self.tracks = []
        self.waypoints = []

        ## Code for parsing in from file
        with open(self.filepath, 'r') as gpx_file:
            data = gpxpy.parse(gpx_file)

        for waypoint in data.waypoints:
            self.waypoints.append(GPXPoint(waypoint.name, waypoint.latitude, waypoint.longitude, waypoint.elevation, waypoint.time))

        for route in data.routes:
            route_name = route.name if route.name else "Unnamed Route"
            track = GPXTrack(route_name)
            for point in route.points:
                track.points.append(GPXPoint(point.name, point.latitude, point.longitude, point.elevation, point.time))
            self.tracks.append(track)

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

class GPXFileData(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    filename = db.Column(db.String(120), index = True, unique = True, nullable = False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    upload_time = db.Column(db.DateTime, index = True, default = datetime.utcnow)
