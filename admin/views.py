# IMPORTS
import random
from flask import Blueprint, render_template, flash, redirect, url_for
from sqlalchemy.orm import make_transient

from app import db, requires_roles
from models import User, Draw, decrypt
from flask_login import login_required, current_user

from users.forms import RegisterForm

# CONFIG
admin_blueprint = Blueprint('admin', __name__, template_folder='templates')


# VIEWS
# view admin homepage
@admin_blueprint.route('/admin')
@requires_roles('admin')
@login_required
def admin():
    return render_template('admin/admin.html', name=current_user.firstname)


# create a new winning draw
@admin_blueprint.route('/generate_winning_draw')
@requires_roles('admin')
@login_required
def generate_winning_draw():
    # get current winning draw
    current_winning_draw = Draw.query.filter_by(master_draw=True).first()
    lottery_round = 1

    # if a current winning draw exists
    if current_winning_draw:
        # update lottery round by 1
        lottery_round = current_winning_draw.lottery_round + 1

        # delete current winning draw
        db.session.delete(current_winning_draw)
        db.session.commit()

    # get new winning numbers for draw
    winning_numbers = random.sample(range(1, 60), 6)
    winning_numbers.sort()
    winning_numbers_string = ''
    for i in range(6):
        winning_numbers_string += str(winning_numbers[i]) + ' '
    winning_numbers_string = winning_numbers_string[:-1]

    # create a new draw object.
    new_winning_draw = Draw(user_id=current_user.id, numbers=winning_numbers_string, master_draw=True,
                            lottery_round=lottery_round, draw_key=current_user.draw_key)

    # add the new winning draw to the database
    db.session.add(new_winning_draw)
    db.session.commit()

    # re-render admin page
    flash("New winning draw %s added." % winning_numbers_string)
    return redirect(url_for('admin.admin'))


# view current winning draw
@admin_blueprint.route('/view_winning_draw')
@requires_roles('admin')
@login_required
def view_winning_draw():
    # get winning draw from DB
    current_winning_draw = Draw.query.filter_by(master_draw=True, been_played=False).first()

    # if a winning draw exists
    if current_winning_draw:
        '''
        # Decrypting winning draw using symmetric decryption
        make_transient(current_winning_draw)
        current_winning_draw = decrypt(current_winning_draw.numbers, current_user.draw_key)
        '''

        #  Decrypting winning draw using asymmetric decryption
        make_transient(current_winning_draw)
        current_winning_draw.numbers = current_winning_draw.view_draw(current_user.private_key)

        # re-render admin page with current winning draw and lottery round
        return render_template('admin/admin.html', winning_draw=current_winning_draw, name=current_user.firstname)

    # if no winning draw exists, rerender admin page
    flash("No valid winning draw exists. Please add new winning draw.")
    return redirect(url_for('admin.admin'))


# view lottery results and winners
@admin_blueprint.route('/run_lottery')
@requires_roles('admin')
@login_required
def run_lottery():
    # get current unplayed winning draw
    current_winning_draw = Draw.query.filter_by(master_draw=True, been_played=False).first()

    # if current unplayed winning draw exists
    if current_winning_draw:

        '''
        # Decrypting winning draw using symmetric decryption
        current_winning_draw = decrypt(current_winning_draw.numbers, current_user.draw_key)
        '''

        #  Decrypting winning draw using asymmetric decryption
        current_winning_draw.numbers = current_winning_draw.view_draw(current_user.private_key)

        # get all unplayed user draws
        user_draws = Draw.query.filter_by(master_draw=False, been_played=False).all()
        results = []

        # if at least one unplayed user draw exists
        if user_draws:

            # update current winning draw as played
            current_winning_draw.been_played = True
            db.session.add(current_winning_draw)
            db.session.commit()

            # for each unplayed user draw
            for draw in user_draws:

                # get the owning user (instance/object)
                user = User.query.filter_by(id=draw.user_id).first()

                '''
                # Decrypting draw numbers using symmetric encryption
                draw.numbers = decrypt(draw.numbers, user.draw_key)
                '''

                # Decrypting draw numbers using asymmetric encryption
                draw.numbers = draw.view_draw(user.private_key)

                # if user draw matches current unplayed winning draw
                if draw.numbers == current_winning_draw.numbers:
                    # add details of winner to list of results
                    results.append((current_winning_draw.lottery_round, draw.numbers, draw.user_id, user.email))

                    # update draw as a winning draw (this will be used to highlight winning draws in the user's
                    # lottery page)
                    draw.matches_master = True

                # update draw as played
                draw.been_played = True

                # update draw with current lottery round
                draw.lottery_round = current_winning_draw.lottery_round

                # commit draw changes to DB
                db.session.add(draw)
                db.session.commit()

            # if no winners
            if len(results) == 0:
                flash("No winners.")

            return render_template('admin/admin.html', results=results, name=current_user.firstname)

        flash("No user draws entered.")
        return admin()

    # if current unplayed winning draw does not exist
    flash("Current winning draw expired. Add new winning draw for next round.")
    return redirect(url_for('admin.admin'))


# view all registered users
@admin_blueprint.route('/view_all_users')
@requires_roles('admin')
@login_required
def view_all_users():
    current_users = User.query.filter_by(role='user').all()

    return render_template('admin/admin.html', name=current_user.firstname, current_users=current_users)


# view all user activity
@admin_blueprint.route('/view_all_activity', methods=['POST'])
@requires_roles('admin')
@login_required
def view_all_activity():
    user_activity = User.query.filter_by(role='user').all()

    return render_template('admin/admin.html', name=current_user.firstname, content=user_activity)


# view last 10 log entries
@admin_blueprint.route('/logs')
@requires_roles('admin')
@login_required
def logs():
    with open("lottery.log", "r") as f:
        content = f.read().splitlines()[-10:]
        content.reverse()

    return render_template('admin/admin.html', logs=content, name=current_user.firstname)


@admin_blueprint.route('/register_admin', methods=['GET', 'POST'])
@requires_roles('admin')
@login_required
def register_admin():
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
        new_admin = User(email=form.email.data,
                         firstname=form.firstname.data,
                         lastname=form.lastname.data,
                         birthdate=form.birthdate.data,
                         phone=form.phone.data,
                         password=form.password.data,
                         postcode=form.postcode.data,
                         login_count='0',
                         role='admin')

        # add the new admin to the database
        db.session.add(new_admin)
        db.session.commit()
        flash("A new admin has been added successfully")
        # sends user to login page
        return redirect(url_for('admin.admin'))
    # if request method is GET or form not valid re-render signup page
    return render_template('users/register.html', form=form)
