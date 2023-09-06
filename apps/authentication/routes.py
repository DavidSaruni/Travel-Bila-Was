# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from flask import render_template, redirect, request, url_for
from flask_login import (
    current_user,
    login_user,
    logout_user
)
import base64
from flask_dance.contrib.github import github

from apps import db, login_manager
from flask_login import current_user, login_required
from apps.authentication import blueprint
from apps.authentication.forms import LoginForm, CreateAccountForm
from apps.authentication.models import User,Solo,Event,Institution,Parcel,Profile


from apps.authentication.util import verify_pass

@blueprint.route('/')
def route_default():
    return redirect(url_for('authentication_blueprint.login'))

# Login & Registration

@blueprint.route("/github")
def login_github():
    """ Github login """
    if not github.authorized:
        return redirect(url_for("github.login"))

    res = github.get("/user")
    return redirect(url_for('home_blueprint.index'))

@blueprint.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm(request.form)
    if 'login' in request.form:

        # read form data
        user_id  = request.form['username'] # we can have here username OR email
        password = request.form['password']

        # Locate user
        user = User.find_by_username(user_id)

        # if user not found
        if not user:

            user = User.find_by_email(user_id)

            if not user:
                return render_template( 'accounts/login.html',
                                        msg='Unknown User or Email',
                                        form=login_form)

        # Check the password
        if verify_pass(password, user.password):

            login_user(user)
            return redirect(url_for('authentication_blueprint.route_default'))

        # Something (user or pass) is not ok
        return render_template('accounts/login.html',
                               msg='Wrong user or password',
                               form=login_form)

    if not current_user.is_authenticated:
        return render_template('accounts/login.html',
                               form=login_form)
    return redirect(url_for('home_blueprint.index'))


@blueprint.route('/register', methods=['GET', 'POST'])
def register():
    create_account_form = CreateAccountForm(request.form)
    if 'register' in request.form:

        username = request.form['username']
        email = request.form['email']
        role = request.form['role']

        # Check usename exists
        user = User.query.filter_by(username=username).first()
        if user:
            return render_template('accounts/register.html',
                                   msg='Username already registered',
                                   success=False,
                                   form=create_account_form)

        # Check email exists
        user = User.query.filter_by(email=email).first()
        if user:
            return render_template('accounts/register.html',
                                   msg='Email already registered',
                                   success=False,
                                   form=create_account_form)

        # else we can create the user
        user = User(**request.form)
        db.session.add(user)
        db.session.commit()

        # Delete user from session
        logout_user()

        return render_template('accounts/register.html',
                               msg='User created successfully.',
                               success=True,
                               form=create_account_form)

    else:
        return render_template('accounts/register.html', form=create_account_form)


@blueprint.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('authentication_blueprint.login')) 

# Errors

@login_manager.unauthorized_handler
def unauthorized_handler():
    return render_template('home/page-403.html'), 403


@blueprint.errorhandler(403)
def access_forbidden(error):
    return render_template('home/page-403.html'), 403


@blueprint.errorhandler(404)
def not_found_error(error):
    return render_template('home/page-404.html'), 404


@blueprint.errorhandler(500)
def internal_error(error):
    return render_template('home/page-500.html'), 500


@blueprint.route('/solo', methods=['GET', 'POST'])
@login_required
def trip():
    if request.method == 'POST':
        pick_up = request.form['Location']
        destination = request.form['destination']
        seats = int(request.form['seats'])
        date = request.form['TravelDate']
        time = request.form['Time']
        amount = int(request.form['amount'])

        new_booking = Solo(
            username=current_user.username,
            Pick_Up=pick_up,
            Destination=destination,
            Seats=seats,
            Date=date,
            Time=time,
            Amount=amount
        )

        try:
            new_booking.save()  
            return redirect(url_for('home_blueprint.index'))  
        except Exception as e:
            
            print("Error:", str(e))

    return render_template('home/solo-travel.html')  


@blueprint.route('/event', methods=['GET', 'POST'])
@login_required
def event():
    if request.method == 'POST':
        event_type = request.form['event_type']
        location = request.form['location']
        destination = request.form['destination']
        constituency= request.form['constituency']
        town =request.form['town']
        number_pass = int(request.form['matatu'])
        date = request.form['date']
        time = request.form['time']
        amount = int(request.form['amount'])

        new_booking = Event(
            username=current_user.username,
            location=location,
            Destination=destination,
            constituency=constituency,
            town=town,
            number_pass=number_pass,
            Date=date,
            Time=time,
            Amount=amount
        )

        try:
            new_booking.save()  
            return redirect(url_for('home_blueprint.index'))  
        except Exception as e:
            
            print("Error:", str(e))

    return render_template('home/event-travel.html')  



@blueprint.route('/Institution', methods=['GET', 'POST'])
@login_required
def institution():
    if request.method == 'POST':
        pick_up = request.form['location']
        destination = request.form['destination']
        seats = int(request.form['seats'])
        date = request.form['date']
        time = request.form['time']
        amount = int(request.form['amount'])

        new_booking = Institution(
            username=current_user.username,
            Pick_Up=pick_up,
            Destination=destination,
            Seats=seats,
            Date=date,
            Time=time,
            Amount=amount
        )

        try:
            new_booking.save()  
            return redirect(url_for('home_blueprint.index'))  
        except Exception as e:
            
            print("Error:", str(e))

    return render_template('home/student-travel.html')  



@blueprint.route('/Parcel', methods=['GET', 'POST'])
@login_required
def parcel():
    if request.method == 'POST':
        pick_up = request.form['location']
        destination = request.form['destination']
        photo = int(request.form['photo'])
        amount = int(request.form['amount'])

        new_booking = Parcel(
            username=current_user.username,
            Pick_Up=pick_up,
            Destination=destination,
            photo=photo,
            Amount=amount
        )

        try:
            new_booking.save()  
            return redirect(url_for('home_blueprint.index'))  
        except Exception as e:
            
            print("Error:", str(e))

    return render_template('home/parcel-transport.html')  



@blueprint.route('/profile.html', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        fname = request.form['fname']
        lname = request.form['lname']
        address = request.form['address']
        bio = request.form['bio']
        photo = request.files['photo'].read()

        record = Profile.query.filter_by(username=current_user.username).first()

        if record is not None:
            # Update the existing user profile
            record.username = current_user.username
            record.email = current_user.email
            record.firstName = fname
            record.lastName = lname
            record.address = address
            record.bio = bio
            record.image = photo

            try:
                db.session.commit()
            except Exception as e:
                print("Error:", str(e))
                db.session.rollback()
        else:
            # Create a new user profile
            new_profile = Profile(
                username=current_user.username,
                email=current_user.email,
                firstName=fname,
                lastName=lname,
                address=address,
                image=photo,
                bio=bio
            )

            try:
                db.session.add(new_profile)
                db.session.commit()
            except Exception as e:
                print("Error:", str(e))
                db.session.rollback()

    # Retrieve the updated or newly created profile record
    data = Profile.query.filter_by(username=current_user.username).first()
    if data:
        image=data.image
        image_base64=base64.b64encode(image).decode('utf-8')
        if data.image:
            return render_template('home/profile.html', data=data,image_base64=image_base64)
        
    return render_template('home/profile.html', data=data)



@blueprint.route('/index')
@login_required
def index():
    user_bookings = Solo.query.filter_by(username=current_user.username).all()
    data = Institution.query.filter_by(username=current_user.username).all()
    event_info = Event.query.filter_by(username=current_user.username).all()
    parcel_info = Parcel.query.filter_by(username=current_user.username).all()


    all_user_bookings = Solo.query.all()
    count = len(all_user_bookings)
    all_data = Institution.query.all()
    count2  =len(all_data)
    all_event_info = Event.query.all()
    count3  =len(all_event_info)
    all_parcel_info = Parcel.query.all()
    count4  =len(all_parcel_info)

    count=count+count2+count3+count4
    per_cent=int(count/50*100)

    return render_template('home/index.html',count=count,per_cent=per_cent, bookings=user_bookings,institution=data,event_info=event_info,parcel_info=parcel_info,all_data=all_data,all_event_info=all_event_info,all_parcel_info=all_parcel_info,all_user_bookings=all_user_bookings)

@blueprint.route('/pro')
def pro():
    record = Profile.query.filter_by(username=current_user.username).first()
    return render_template('home/pro.html',record=record)