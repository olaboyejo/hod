from functools import wraps
from flask.ext.bootstrap import Bootstrap
from flask import Flask, render_template, redirect, url_for, request, session, flash, g
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.wtf import Form
from wtforms import TextField, StringField, SubmitField, DateTimeField, PasswordField, BooleanField, validators, SelectField
from wtforms import Form as WTForm
from wtforms.validators import Required
from werkzeug.security import check_password_hash
from flask.ext.migrate import Migrate, MigrateCommand
from flask.ext.script import Manager
from datetime import datetime
app = Flask(__name__)
app.config['SECRET_KEY'] = 'we love you'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hod.db'
app.config['DEBUG'] = True

bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
manager = Manager(app)

migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)

from models import *


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
   
class LoginForm(WTForm):
    username = StringField('Username', validators=[Required()])
    password = PasswordField('Password', validators=[Required()])
    submit = SubmitField('Submit')


class UserAppointmentForm(WTForm):
    test_id = SelectField('Test', coerce=int)
    moment = DateTimeField('Appointment Date/Time', format='%Y-%m-%d %H:%M')

class AppointmentForm(WTForm):
    test_id = SelectField('Test', coerce=int)
    moment = DateTimeField('Appointment Date/Time', format='%Y-%m-%d %H:%M')
    email = TextField('Email Address', [validators.Length(min=6, max=120), validators.Email(), validators.Required()])

class RegistrationForm(WTForm):
    username = TextField('Username', [validators.Length(min=4, max=25)])
    email = TextField('Email Address', [validators.Length(min=6, max=120), validators.Email()])
    password = PasswordField('New Password', [
        validators.Required(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')
    role_id = 3    

@app.route('/')
def index():
    return render_template('index.html', logged_in=session.get('logged_in'), username=session.get('username'))

@app.route('/user/<username>')
@login_required
def home(username):
    if username == session['username']:
      dates = connect_db(username)
      
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
        form = UserAppointmentForm(request.form)
        form.test_id.choices = [(g.id, g.test) for g in Test.query.order_by('id')]
        if request.method == 'POST' and form.validate():
            moment = form.moment.data
            user = session.get('username')
            user_id = User.query.filter_by(username = user).first().id
            email = User.query.filter_by(username = user).first().email
            test_id = form.test_id.data
            appointment = MakeAppointment(moment, user_id, test_id, email, result)
            db.session.add(appointment)
            db.session.commit()
            flash('Thanks for making an appointment')
            return redirect(url_for('index'))
        return render_template('userappointment.html', form=form, logged_in=session.get('logged_in'), username=session.get('username'), current_time=current_time)
    else:
        form = AppointmentForm(request.form)
        form.test_id.choices = [(g.id, g.test) for g in Test.query.order_by('id')]
        if request.method == 'POST' and form.validate():
            moment = form.moment.data
            email = form.email.data
            test_id = form.test_id.data
            appointment = MakeAppointment(moment, user_id, test_id, email, result)
            db.session.add(appointment)
            db.session.commit()
            flash('Thanks for making an appointment')
            return redirect(url_for('index'))
        return render_template('appointment.html', form=form, current_time=current_time)

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
        user_check = User.query.filter_by(username=username).first()
        if user_check is not None and check_password_hash(user_check.password, password):
            session['logged_in'] = True
            session['username'] = username
            flash('You just logged in successfully')
            return redirect(url_for('home', username=username))
        else:
            error = ' Invalid Credentials '
    return render_template('login.html', error=error, form=form, username=session.get('username'))

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
    return render_template('adminlogin.html', error=error, form=form, username=session.get('username'))

@app.route('/logout')
@login_required
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    flash('you just logged out. Why the hell would you do that?')
    return redirect(url_for('index'))

def connect_db(username):
    id = User.query.filter_by(username = username).first().id
    date_check = MakeAppointment.query.filter_by(user_id = id).first()
    if date_check is None:
        dates = 'no appointment'
    else:
        dates = MakeAppointment.query.filter_by(user_id = id).first().moment
    return dates

def get_users_db():
    users = User.query.filter_by(role_id = 3).all()
    return users

if __name__ == '__main__':
    manager.run()
