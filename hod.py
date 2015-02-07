#!/usr/bin/env python

import string
import random
from functools import wraps
from flask.ext.bootstrap import Bootstrap
from flask import Flask, render_template, redirect, url_for, request, session, flash, g, current_app
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.wtf import Form
from wtforms import TextField, StringField, SubmitField, DateTimeField, PasswordField, BooleanField, validators, SelectField
from wtforms import Form as WTForm
from wtforms.validators import Required
from werkzeug.security import check_password_hash, generate_password_hash
from flask.ext.migrate import Migrate, MigrateCommand
from flask.ext.script import Manager
from flask.ext.login import LoginManager, login_user, logout_user
from flask.ext.mail import Mail, Message
from datetime import datetime
from threading import Thread
from wtforms_components import DateRange


app = Flask(__name__)
app.config.from_object('config.DefaultConfig')

bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
manager = Manager(app)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)

migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)

from models import *



login_manager.login_view = 'login'


def async(f):
    def wrapper(*args, **kwargs):
        thr = Thread(target=f, args=args, kwargs=kwargs)
        thr.start()
    return wrapper

@async
def send_async_email(msg):
    with app.app_context():
        mail.send(msg)


def account_creation(email, default_password):
    text = """Congratulations,
                     You have been registered with house of diagnostics. Your default details are
                     username %s
                     password %s
                     To change your password and complete your profile go to ......
                     Thanks

                     House of Diagnostics""" %(email, default_password)
    return text

def get_user_id(email):
    user = User.query.filter_by(email = email).first()
    if user == None:
        default_password = password_generator(8)
        db.session.add(User(email, default_password))
        db.session.commit
        registration_mail(email, default_password)
    user_id = User.query.filter_by(email = email).first().id
    return user_id


def registration_mail(email,default_password):
    msg = Message(
              'Registration Confirmation',
	       sender='house.of.diagnostics.mail@gmail.com',
	       recipients=
               [email])
    msg.body = account_creation(email,default_password)
    send_async_email(msg)
    return "Sent"

def appointment_mail(email, moment, test):
    msg = Message(
              'Appointment Confirmation',
	       sender='house.of.diagnostics.mail@gmail.com',
	       recipients=
               [email])
    msg.body = ("We are pleased to inform you that you appointment for %s on %s has been confirmed." %(test, moment.strftime("%B %d, %Y")))
    send_async_email(msg)
    return "Sent"

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('You need to login first.')
            return redirect(url_for('login'))
    return wrap

def adminlogin_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'admin' in session:
            return f(*args, **kwargs)
        else:
            flash('You need to be an administrator to see this page')
            return redirect(url_for('adminlogin'))
    return wrap


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))
   
class LoginForm(WTForm):
    username = StringField('Username', validators=[Required()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('remember_me', default=False)
    submit = SubmitField('Submit')


class UserAppointmentForm(WTForm):
    test_id = SelectField('Test', coerce=int)
    moment = DateTimeField('Appointment Date/Time', format='%Y-%m-%d %H:%M', validators=[DateRange(min=datetime.now())])
    email = TextField('Email Address', [validators.Length(min=6, max=120), validators.Email(), validators.Required()])
    submit = SubmitField('Submit')

class AppointmentForm(WTForm):
    test_id = SelectField('Test', coerce=int)
    moment = DateTimeField('Appointment Date/Time', format='%Y-%m-%d %H:%M', validators=[DateRange(min=datetime.now())])
    email = TextField('Email Address', [validators.Length(min=6, max=120), validators.Email(), validators.Required()])
    submit = SubmitField('Submit')

def update_user(form, user_details):
  default_email = user_details[0]
  default_firstname = user_details[1]
  default_dob= user_details[3]
  default_surname = user_details[2]
  class UserUpdateForm(WTForm):
    firstname = TextField('Given Names', [validators.Length(min=0, max=50)], default=default_firstname)
    surname = TextField('Surname', [validators.Length(min=0, max=50)], default=default_surname)
    email = TextField('Email Address', [validators.Email()], default=default_email)
    password = PasswordField('New Password', [validators.Length(min=0, max=50),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')
    dob = DateTimeField('Date of Birth', format='%Y-%m-%d', default=default_dob)
  update_form = UserUpdateForm(form)
  return update_form

class RegistrationForm(WTForm):
    firstname = TextField('Given Names', [validators.Length(min=4, max=50)])
    surname = TextField('Surname', [validators.Length(min=4, max=50)])
    email = TextField('Email Address', [validators.Email()])
    password = PasswordField('New Password', [
        validators.Required(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')
    address = TextField('Contact Address', [validators.Length(min=4, max=50)])
    dob = DateTimeField('Date of Birth', format='%Y-%m-%d')

@app.route('/')
def index():
    return render_template('index.html', logged_in=session.get('logged_in'), username=session.get('username'))


@app.route('/user/<username>/profile')
@login_required
def profile(username):
    if username == session['username']:
      dates = get_appointments(username)
      user_details = get_user_details(username)
      return render_template('profile.html', user_details = user_details, username = username)
    else:
      return redirect(url_for('login'))


@app.route('/user/<username>')
@login_required
def home(username):
    if username == session['username']:
      dates = get_next_date(username)
      
      return render_template('home.html', username=username, dates=dates)
    else:
      return redirect(url_for('login'))

@app.route('/userlist')
@adminlogin_required
def adminhome():
      users = get_users_db()
      return render_template('userlist.html', users=users)

@app.route('/appointment', methods=['GET', 'POST'])
def appointment():
    current_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
    moment = ''
    user_id = ''
    test_id = ''
    result = ''
    email =''
    if session.get('username') and session.get('logged_in'):
        form = AppointmentForm(request.form)
        form.test_id.choices = [(g.id, g.test) for g in Test.query.order_by('id')]
        if request.method == 'POST' and form.validate():
            moment = form.moment.data
            user = session.get('username')
            user_id = User.query.filter_by(email = user).first().id
            test_id = form.test_id.data
            appointment = MakeAppointment(moment, user_id, test_id)
            db.session.add(appointment)
            db.session.commit()
            flash('Thanks for making an appointment')
            appointment_mail(user, moment, test=Test.query.filter_by(id = test_id).first().test)
            return redirect(url_for('index'))
        return render_template('appointment.html', form=form, logged_in=session.get('logged_in'), username=session.get('username'), current_time=current_time)
    else:
        form = AppointmentForm(request.form)
        form.test_id.choices = [(g.id, g.test) for g in Test.query.order_by('id')]
        if request.method == 'POST' and form.validate():
            moment = form.moment.data
            email = form.email.data
            test_id = form.test_id.data
            user_id = get_user_id(email)
            appointment = MakeAppointment(moment, user_id, test_id)
            db.session.add(appointment)
            db.session.commit()
            flash('Thanks for making an appointment')
            appointment_mail(email, moment, test=Test.query.filter_by(id = test_id).first().test)
            return redirect(url_for('index'))
        return render_template('appointment.html', form=form, current_time=current_time)


@app.route('/user/<username>/edit', methods=['GET', 'POST'])
@login_required
def user_update(username):
    user_details = get_user_details(username)
    form = update_user(request.form, user_details)
    if request.method == 'POST' and form.validate():
        id = get_user_id(username)
        print id
        user = User.query.get(id)
        user.given_name = form.firstname.data
        user.surname = form.surname.data
        user.dob = form.dob.data
        user.email = form.email.data
        if len(form.password.data) < 6:
            flash("Password should at least 6 characters\nPassword Remains unchanged")
            user.password = user.password
        else :
            user.password = generate_password_hash(form.password.data)
        db.session.commit()
        flash('Settings Updated')
        return redirect(url_for('profile', username=username))
    return render_template('update.html', form=form, user_details=user_details, methods=['GET','POST'])

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        user = User(form.username.data, form.email.data,
                    form.password.data, 3)
        db.session.add(user)
        db.session.commit()
        flash('Thanks for registering')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    username = None
    form = LoginForm(request.form)
    if form.validate() and request.method == 'POST':
        username = form.username.data
        password = form.password.data
        remember_me = form.remember_me.data
        user_check = User.query.filter_by(email=username).first()
        if user_check is not None and check_password_hash(user_check.password, password):
            session['logged_in'] = True
            session['username'] = username
            if remember_me == False:
                login_user(user_check)
            else:
                login_user(user_check,remember=True)
            flash('You just logged in successfully')
            return redirect(url_for('home', username=username))
        else:
            error = ' Invalid Credentials '
    return render_template('login.html', error=error, form=form)

@app.route('/adminlogin', methods=['GET', 'POST'])
def adminlogin():
    error = None
    username = None
    form = LoginForm(request.form)
    if form.validate() and request.method == 'POST':
        username = form.username.data
        password = form.password.data
        user_check = User.query.filter_by(username=username).first()
        if user_check is not None and check_password_hash(user_check.password, password) and user_check.role_id ==1:
            session['logged_in'] = True
            session['admin'] = True
            session['username'] = username
            flash('You just logged in successfully')
            return redirect(url_for('adminhome'))
        else:
            error = ' Invalid Credentials '
    return render_template('adminlogin.html', error=error, form=form)

@app.route('/logout')
@login_required
def logout():
    session.pop('logged_in', None)
    session.pop('admin', None)
    session.pop('username', None)
    logout_user()
    flash('you just logged out. Why the hell would you do that?')
    return redirect(url_for('index'))


def get_appointments_db(username):
    dates_tests = []
    id = User.query.filter_by(email = username).first().id
    date_check = MakeAppointment.query.filter_by(user_id = id).all()
    dates_tests = user_appointments(date_check)
    return dates_tests

def user_appointments(date_check):
    dates_tests = []
    if date_check is None:
        dates_tests = [("no dates", "no tests")]
    else:
        for appointment in date_check:
            date = appointment.appointment_date
            test_id = appointment.test_id
            test = Test.query.filter_by(id=test_id).first()
            date_test = (date, test)
            dates_tests.append(date_test)
    return dates_tests


def get_user_details(username):
    user  = User.query.filter_by(email=username).first()
    given_name = user.given_name
    surname = user.surname
    dob = user.dob
    appointments = user_appointments(user.appointments)
    user_details = [user, given_name, surname, dob, appointments]
    print user_details[4][0]
    print user_details[4][1]
    return user_details

def get_appointments(username):
    dates_tests = get_appointments_db(username)
    appointments = sorted(dates_tests)
    return appointments

def get_next_date(username):
    dates_tests = get_appointments_db(username)
    next_appointment = sorted(dates_tests)[0]
    return next_appointment

def password_generator(length=13, chars=string.ascii_letters +string.digits + '!@#$%^&*()'):
    return ''.join(random.choice(chars) for x in range(length))

def get_users_db():
    users = User.query.filter_by(role_id = 3).all()
    return users

if __name__ == '__main__':
    manager.run()
