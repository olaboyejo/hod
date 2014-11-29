#default configuration

class DefaultConfig():
    SECRET_KEY = 'we love you'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///hod.db'
    DEBUG = True
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = 'house.of.diagnostics.mail@gmail.com'
    MAIL_PASSWORD = 'amaechiynwa'

