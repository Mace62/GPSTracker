from sqlalchemy import Enum, DateTime
from datetime import datetime
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

class Subscriptions(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subscription_type = db.Column(Enum('Weekly', 'Monthly', 'Yearly', name='subscription_types'), index = True, nullable = False)
    payment_date = db.Column(DateTime, default=datetime.utcnow)