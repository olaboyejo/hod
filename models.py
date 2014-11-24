#!/usr/bin/env python
from hod import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
class MakeAppointment(db.Model):

    __tablename__ = 'appointments'
    id = db.Column(db.Integer, primary_key=True)
    moment = db.Column(db.DateTime, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    test_id = db.Column(db.Integer, db.ForeignKey('tests.id'))
    result = db.Column(db.String, nullable=True)

    def __init__(self, moment, user_id, test_id, result):
        self.moment = moment
        self.user_id = user_id
        self.test_id = test_id
        self.result = result
    def __repr__(self):
        return '{}---{}---{}'.format(self.moment, self.user_id, self.test_id)

class User(db.Model):
    __tablename__ = 'users'
 
    id = db.Column(db.Integer, primary_key=True)
    given_name = db.Column(db.String, nullable=True)
    surname = db.Column(db.String, nullable=True)
    address = db.Column(db.String, nullable=True)
    dob = db.Column(db.DateTime, nullable=True)
    email = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)
    appointments = db.relationship("MakeAppointment", backref="user")

    def __init__(self, email, password):
        self.email = email
        self.password = password

    def __repr__(self):
        return '{}'.format(self.email)


class Administrator(db.Model):

    __tablename__ = 'administrators'
   

    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String, nullable=False)
    username = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)


    def __init__(self, username, password, role):
        self.username = username
        self.password = password
        self.role = role

    def __repr__(self):
        return '{}'.format(self.username)

class Test(db.Model):

    __tablename__ = 'tests'
 
    id = db.Column(db.Integer, primary_key=True)
    test = db.Column(db.String, nullable=False)
    appointments = db.relationship("MakeAppointment", backref="test")

    def __init__(self, test):
        self.test = test

    def __repr__(self):
        return '{}'.format(self.test)


