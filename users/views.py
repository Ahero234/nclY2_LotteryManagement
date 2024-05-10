# IMPORTS
import logging
from datetime import datetime

from flask import Blueprint, render_template, flash, redirect, url_for, session, request
from flask_login import login_user, logout_user, current_user, login_required
from markupsafe import Markup

from app import db
from models import User
from users.forms import RegisterForm, LoginForm, PasswordForm

# CONFIG
users_blueprint = Blueprint('users', __name__, template_folder='templates')


# VIEWS
# view registration
@users_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    # create signup form object
    form = RegisterForm()

    # if request method is POST or form is valid
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        # if this returns a user, then the email already exists in database

        # if email already exists redirect user back to signup page with error message so user can try again
        if user:
            flash('Email address already exists')
            return render_template('users/register.html', form=form)

        # create a new user with the form data
        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        birthdate=form.birthdate.data,
                        phone=form.phone.data,
                        password=form.password.data,
                        postcode=form.postcode.data,
                        login_count='0',
                        role='user')

        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()
        session['email'] = new_user.email
        logging.warning('SECURITY - User registration [%s %s]', form.email.data, request.remote_addr)

        # sends user to login page
        return redirect(url_for('users.setup_2fa'))
    # if request method is GET or form not valid re-render signup page
    return render_template('users/register.html', form=form)


# view user login
@users_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_anonymous:
        if not session.get('authentication_attempts'):
            session['authentication_attempts'] = 0
        print("attempts: " + str(session.get('authentication_attempts')))
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if not user or not user.verify_password(form.password.data) or not user.verify_pin(form.pin.data) \
                    or not user.verify_postcode(form.postcode.data):
                logging.warning('SECURITY - Invalid login [%s %s]', form.email.data, request.remote_addr)

                session['authentication_attempts'] += 1
                if session.get('authentication_attempts') >= 3:
                    flash(Markup('Number of incorrect login attempts exceeded. '
                                 'Please click <a href="/reset">here</a> to reset.'))
                    return render_template('users/login.html')

                flash('Please check your login details and try again, '
                      '{} login attempts remaining'.format(3 - session.get('authentication_attempts')))
                return render_template('users/login.html', form=form)
            else:
                login_user(user)
                current_user.current_login = datetime.now()
                current_user.last_login = current_user.current_login
                current_user.current_ip = request.remote_addr
                current_user.last_ip = current_user.current_ip
                current_user.login_count = str(int(current_user.login_count) + 1)
                db.session.commit()
                logging.warning('SECURITY - Log in [%s %s %s %s]', current_user.id, current_user.email, current_user.role, request.remote_addr)
                session['authentication_attempts'] = 0
                if current_user.role == 'user':
                    return redirect(url_for('lottery.lottery'))
                else:
                    return redirect(url_for('admin.admin'))
        return render_template('users/login.html', form=form)
    else:
        flash("Logged in")
        return render_template('main/index.html')


@users_blueprint.route('/reset')
def reset():
    session['authentication_attempts'] = 0
    return redirect(url_for('users.login'))


# view user account
@users_blueprint.route('/account')
@login_required
def account():
    return render_template('users/account.html',
                           acc_no=current_user.id,
                           email=current_user.email,
                           firstname=current_user.firstname,
                           lastname=current_user.lastname,
                           phone=current_user.phone,
                           birthdate=current_user.birthdate,
                           postcode=current_user.postcode)


@users_blueprint.route("/setup_2fa")
def setup_2fa():
    if 'email' not in session:
        return redirect(url_for('main.index'))
    user = User.query.filter_by(email=session['email']).first()
    if not user:
        return redirect(url_for('main.index'))
    del session['email']

    return render_template('users/setup_2fa.html', username=user.email, uri=user.get_2fa_uri()), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@users_blueprint.route('/logout')
def logout():
    logging.warning('SECURITY - Log out [%s %s %s %s]', current_user.id, current_user.email, current_user.role, request.remote_addr)
    logout_user()
    session['authentication_attempts'] = 0
    return redirect(url_for('index'))


@users_blueprint.route('/update_password', methods=['GET', 'POST'])
def update_password():
    form = PasswordForm()

    if form.validate_on_submit():
        # check if current password entered by user does not match current password stored for user in the database.
        if not current_user.password == form.current_password.data:
            flash("Incorrect password. Please try again")
            return redirect(url_for('users.update_password'))

        # check if new password entered by the user matches current password stored for user in the database.
        if current_user.password == form.new_password.data:
            flash("The new password cannot be the same as the current password. Please try again")
            return redirect(url_for('users.update_password'))

        current_user.password = form.new_password.data
        db.session.commit()
        flash('Password changed successfully')
        logging.warning('SECURITY - Update password [%s %s %s %s]', current_user.id, current_user.email, current_user.role, request.remote_addr)

        return redirect(url_for('users.account'))

    return render_template('users/update_password.html', form=form)
