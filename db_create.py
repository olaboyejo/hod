from datetime import datetime
from hod import db
from models import MakeAppointment, User, Test, Role

db.drop_all()

#Create db and db tables

db.create_all()

#insert

db.session.add(Role('Administrator'))
db.session.add(Role('Staff'))
db.session.add(Role('Customer'))
db.session.add(Test('Pregnancy'))
db.session.add(Test('Blood Type'))
db.session.add(Test('HIV'))
db.session.add(Test('DNA'))
db.session.add(User('ama', 'ama@gmail.com', 'you-will-never-walk-alone', 1))
db.session.add(User('amaka', 'amaka@gmail.com', 'you-will-never-walk-alone', 2))
db.session.add(User('chido', 'bashiru@gmail.com', 'you-will-never-walk-alone', 2))
db.session.add(User('bash', 'chidi@gmail.com', 'you-will-never-walk-alone', 2))
db.session.add(User('lola', 'lola@gmail.com', 'you-will-never-walk-alone', 3))
db.session.add(User('yakubu', 'yakubu@gmail.com', 'you-will-never-walk-alone', 3))
db.session.add(User('amina', 'amina@gmail.com', 'you-will-never-walk-alone', 3))
db.session.add(MakeAppointment(datetime.utcnow(),5,1,"", ""))
db.session.add(MakeAppointment(datetime.utcnow(),7,1,"",""))
db.session.add(MakeAppointment(datetime.utcnow(),6,3,"bash@gmail.com", "negative"))
db.session.add(MakeAppointment(datetime.utcnow(),6,3,"bash@gmail.com",""))


#Commit

db.session.commit()

