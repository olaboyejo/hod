#!/usr/bin/env python
from datetime import datetime
from hod import db
from models import MakeAppointment, User, Test, Administrator

db.drop_all()

#Create db and db tables

db.create_all()

#insert

db.session.add(Test('Pregnancy'))
db.session.add(Test('Blood Type'))
db.session.add(Test('HIV'))
db.session.add(Test('DNA'))
db.session.add(Administrator('ama', 'liverpool','admin'))
db.session.add(Administrator('boye', 'enyimba','admin'))
db.session.add(Administrator('cele', 'green','staff'))
db.session.add(User('amaka@aol.com', 'igobi'))
db.session.add(User('mo@gmail.com', 'vikky'))
db.session.add(User('bashiru@hotmail.com', 'lusaka'))
db.session.add(User('chidi@gmail.com', 'rojenny'))
db.session.add(User('lola@gmail.com', 'titi'))
db.session.add(User('yakubu@gmail.com', 'abuja'))
db.session.add(User('amina@yahoo.com', 'lafia'))
db.session.add(MakeAppointment(datetime.utcnow(),5,1))
db.session.add(MakeAppointment(datetime.utcnow(),7,1))
db.session.add(MakeAppointment(datetime.utcnow(),6,3))


#Commit

db.session.commit()

