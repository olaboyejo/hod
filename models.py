from hod import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
class MakeAppointment(db.Model):

    __tablename__ = 'appointments'
    id = db.Column(db.Integer, primary_key=True)
    moment = db.Column(db.DateTime, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    test_id = db.Column(db.Integer, db.ForeignKey('tests.id'))
    email = db.Column(db.String, nullable=True)
    result = db.Column(db.String, nullable=True)

    def __init__(self, moment, user_id, test_id, email, result):
        self.moment = moment
        self.user_id = user_id
        self.test_id = test_id
        self.email = email
        self.result = result
    def __repr__(self):
        return '{}---{}---{}'.format(self.moment, self.user_id, self.test_id)

class User(db.Model):
    __tablename__ = 'users'
 
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    appointments = db.relationship("MakeAppointment", backref="user")

    def __init__(self, username, email, password, role_id):
        self.username = username
        self.email = email
        self.password = generate_password_hash(password)
        self.role_id = role_id

    def __repr__(self):
        return '{}'.format(self.username)


class Role(db.Model):

    __tablename__ = 'roles'
   

    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String, nullable=False)
    users = db.relationship('User', backref='role')

    def __init__(self, role):
        self.role = role

    def __repr__(self):
        return '{}'.format(self.role)


class Test(db.Model):

    __tablename__ = 'tests'
 
    id = db.Column(db.Integer, primary_key=True)
    test = db.Column(db.String, nullable=False)
    appointments = db.relationship("MakeAppointment", backref="test")

    def __init__(self, test):
        self.test = test

    def __repr__(self):
        return '{}'.format(self.test)


