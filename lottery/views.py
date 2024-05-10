# IMPORTS
from flask import Blueprint, render_template, request, flash, redirect, url_for
from sqlalchemy.orm import make_transient

from app import db, requires_roles
from lottery.forms import DrawForm
from models import Draw, decrypt
from flask_login import login_required, current_user

# CONFIG
lottery_blueprint = Blueprint('lottery', __name__, template_folder='templates')


# VIEWS
# view lottery page
@lottery_blueprint.route('/lottery')
@requires_roles('user')
@login_required
def lottery():
    return render_template('lottery/lottery.html', name=current_user.firstname)


# view all draws that have not been played
@lottery_blueprint.route('/create_draw', methods=['POST'])
@requires_roles('user')
@login_required
def create_draw():
    form = DrawForm()

    if form.validate_on_submit():
        numbers = [form.number1.data, form.number2.data, form.number3.data, form.number4.data, form.number5.data, form.number6.data]
        orderedNumbers = sorted(numbers)

        submitted_numbers = (str(orderedNumbers[0]) + ' '
                             + str(orderedNumbers[1]) + ' '
                             + str(orderedNumbers[2]) + ' '
                             + str(orderedNumbers[3]) + ' '
                             + str(orderedNumbers[4]) + ' '
                             + str(orderedNumbers[5]))
        
        # create a new draw with the form data.
        new_draw = Draw(user_id=current_user.id, numbers=submitted_numbers, master_draw=False, lottery_round=0, draw_key=current_user.draw_key)
        # add the new draw to the database
        db.session.add(new_draw)
        db.session.commit()

        # re-render lottery.page
        flash('Draw %s submitted.' % submitted_numbers)
        return redirect(url_for('lottery.lottery'))

    flash("Each number must be unique")
    return render_template('lottery/lottery.html', name=current_user.firstname, form=form)


# view all draws that have not been played
@lottery_blueprint.route('/view_draws', methods=['POST'])
@requires_roles('user')
@login_required
def view_draws():
    # get all draws that have not been played [played=0]
    playable_draws = Draw.query.filter_by(been_played=False, user_id=current_user.id).all()

    # if playable draws exist
    if len(playable_draws) != 0:
        '''
        # symmetric decryption
        for draw in playable_draws:
            make_transient(draw)
            draw.numbers = decrypt(draw.numbers, current_user.draw_key)
        '''
        # asymmetric decryption
        for draw in playable_draws:
            make_transient(draw)
            draw.numbers = draw.view_draw(current_user.private_key)

        # re-render lottery page with playable draws
        return render_template('lottery/lottery.html', playable_draws=playable_draws, name=current_user.firstname)
    else:
        flash('No playable draws.')
        return lottery()


# view lottery results
@lottery_blueprint.route('/check_draws', methods=['POST'])
@requires_roles('user')
@login_required
def check_draws():
    # get played draws
    played_draws = Draw.query.filter_by(been_played=True).all()

    # if played draws exist
    if len(played_draws) != 0:
        return render_template('lottery/lottery.html', results=played_draws, played=True)

    # if no played draws exist [all draw entries have been played therefore wait for next lottery round]
    else:
        flash("Next round of lottery yet to play. Check you have playable draws.")
        return lottery()


# delete all played draws
@lottery_blueprint.route('/play_again', methods=['POST'])
@requires_roles('user')
@login_required
def play_again():
    Draw.query.filter_by(been_played=True, master_draw=False).delete(synchronize_session=False)
    db.session.commit()

    flash("All played draws deleted.")
    return lottery()
