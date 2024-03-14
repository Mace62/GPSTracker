from flask_login import UserMixin
from app import db
from datetime import datetime


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(64), index = True, unique = True, nullable = False)
    firstname = db.Column(db.String(120), index = True, nullable = False)
    lastname = db.Column(db.String(120), index = True, nullable = False)
    email = db.Column(db.String(120), index = True, unique = True, nullable = False)
    password = db.Column(db.String(120), index = True, nullable = False)
    
    sent_requests = db.relationship('FriendRequest', foreign_keys='FriendRequest.sender_id',
                                    backref='sender', lazy='dynamic')
    received_requests = db.relationship('FriendRequest', foreign_keys='FriendRequest.receiver_id',
                                        backref='receiver', lazy='dynamic')


class Admin(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    
class FriendRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(10), nullable=False)  # Can be 'pending', 'accepted', 'declined'

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, unique = True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)