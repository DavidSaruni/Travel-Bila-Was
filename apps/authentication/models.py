# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from flask_login import UserMixin

from sqlalchemy.orm import relationship
from flask_dance.consumer.storage.sqla import OAuthConsumerMixin

from apps import db, login_manager

from apps.authentication.util import hash_pass

class Users(db.Model, UserMixin):

    __tablename__ = 'users'

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(64), unique=True)
    email         = db.Column(db.String(64), unique=True)
    password      = db.Column(db.LargeBinary)

    oauth_github  = db.Column(db.String(100), nullable=True)

    def __init__(self, **kwargs):
        for property, value in kwargs.items():
            # depending on whether value is an iterable or not, we must
            # unpack it's value (when **kwargs is request.form, some values
            # will be a 1-element list)
            if hasattr(value, '__iter__') and not isinstance(value, str):
                # the ,= unpack of a singleton fails PEP8 (travis flake8 test)
                value = value[0]

            if property == 'password':
                value = hash_pass(value)  # we need bytes here (not plain str)

            setattr(self, property, value)

    def __repr__(self):
        return str(self.username)

    @classmethod
    def find_by_email(cls, email: str) -> "Users":
        return cls.query.filter_by(email=email).first()

    @classmethod
    def find_by_username(cls, username: str) -> "Users":
        return cls.query.filter_by(username=username).first()
    
    @classmethod
    def find_by_id(cls, _id: int) -> "Users":
        return cls.query.filter_by(id=_id).first()
   
    def save(self) -> None:
        try:
            db.session.add(self)
            db.session.commit()
          
        except SQLAlchemyError as e:
            db.session.rollback()
            db.session.close()
            error = str(e.__dict__['orig'])
            raise InvalidUsage(error, 422)
    
    def delete_from_db(self) -> None:
        try:
            db.session.delete(self)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            db.session.close()
            error = str(e.__dict__['orig'])
            raise InvalidUsage(error, 422)
        return

@login_manager.user_loader
def user_loader(id):
    return Users.query.filter_by(id=id).first()

@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    user = Users.query.filter_by(username=username).first()
    return user if user else None

class OAuth(OAuthConsumerMixin, db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="cascade"), nullable=False)
    user = db.relationship(Users)


class Solo(db.Model):

    __tablename__ = 'solo'

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(64), db.ForeignKey('users.username'), nullable=False)
    Pick_Up       = db.Column(db.String(64))
    Destination   = db.Column(db.String(100))
    Seats         = db.Column(db.Integer)
    Date          = db.Column(db.String(10))
    Time          = db.Column(db.String(10))
    Amount        = db.Column(db.Integer)

    def save(self) -> None:
        try:
            db.session.add(self)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            db.session.close()
            raise e

    def __repr__(self):
        return f"Solo(id={self.id}, username={self.username}, Pick_Up={self.Pick_Up}, Destination={self.Destination}, Seats={self.Seats}, Date={self.Date}, Time={self.Time}, Amount={self.Amount})"


class Event(db.Model):

    __tablename__ = 'event'

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(64), db.ForeignKey('users.username'), nullable=False)
    event_type       = db.Column(db.String(64))
    location   = db.Column(db.String(100))
    Destination   = db.Column(db.String(100))
    constituency  = db.Column(db.String(100))
    town           = db.Column(db.String(100))  
    number_pass         = db.Column(db.Integer)
    Date          = db.Column(db.String(10))
    Time          = db.Column(db.String(10))
    Amount        = db.Column(db.Integer)

    def save(self) -> None:
        try:
            db.session.add(self)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            db.session.close()
            raise e

    def __repr__(self):
        return str(self.event_type)


class Institution(db.Model):

    __tablename__ = 'institution'

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(64), db.ForeignKey('users.username'), nullable=False)
    Pick_Up       = db.Column(db.String(64))
    Destination   = db.Column(db.String(100))
    Seats         = db.Column(db.Integer)
    Date          = db.Column(db.String(10))
    Time          = db.Column(db.String(10))
    Amount        = db.Column(db.Integer)

    def save(self) -> None:
        try:
            db.session.add(self)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            db.session.close()
            raise e

    def __repr__(self):
        return str(self.Pick_Up)



class Parcel(db.Model):

    __tablename__ = 'parcel'

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(64), db.ForeignKey('users.username'), nullable=False)
    Pick_Up       = db.Column(db.String(64))
    Destination   = db.Column(db.String(100))
    photo         = db.Column(db.String(100))
    Amount        = db.Column(db.Integer)

    def save(self) -> None:
        try:
            db.session.add(self)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            db.session.close()
            raise e

    def __repr__(self):
        return str(self.Pick_Up)
