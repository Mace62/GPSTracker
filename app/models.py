from app import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(64), index = True, unique = True, nullable = False)
    firstname = db.Column(db.String(120), index = True, nullable = False)
    lastname = db.Column(db.String(120), index = True, nullable = False)
    email = db.Column(db.String(120), index = True, unique = True, nullable = False)
    password = db.Column(db.String(120), index = True, nullable = False)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)