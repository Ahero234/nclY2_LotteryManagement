# IMPORTS
import logging
import os
from functools import wraps
from flask_talisman import Talisman
from dotenv import load_dotenv
from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
from flask_qrcode import QRcode
from flask_login import LoginManager, current_user

load_dotenv()

# CONFIG
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config["SQLALCHEMY_ECHO"] = os.getenv("SQLALCHEMY_ECHO") == "True"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = os.getenv("SQLALCHEMY_TRACK_MODIFICATIONS") == "True"
app.config["RECAPTCHA_PUBLIC_KEY"] = os.getenv("RECAPTCHA_PUBLIC_KEY")
app.config["RECAPTCHA_PRIVATE_KEY"] = os.getenv("RECAPTCHA_PRIVATE_KEY")

csp = {
    'default-src': ['\'self\'',
                    'https://cdnjs.cloudflare.com/ajax/libs/bulma/0.7.2/css/bulma.min.css'],
    'frame-src': ['\'self\'',
                  'https://www.google.com/recaptcha/',
                  'https://recaptcha.google.com/recaptcha/'],
    'script-src': ['\'self\'',
                   '\'unsafe-inline\'',
                   'https://www.google.com/recaptcha/',
                   'https://www.gstatic.com/recaptcha/'],
    'img-src': ['data:']
}

# initialise database
db = SQLAlchemy(app)
qrcode = QRcode(app)
talisman = Talisman(app, content_security_policy=csp)


class SecurityFilter(logging.Filter):
    def filter(self, record):
        return 'SECURITY' in record.getMessage()


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# file handler
file_handler = logging.FileHandler(os.path.join(os.path.dirname(__file__), 'lottery.log'), 'a')
file_handler.setLevel(logging.WARNING)
file_handler.addFilter(SecurityFilter())

formatter = logging.Formatter('%(asctime)s : %(message)s', '%m/%d/%Y %I:%M:%S %p')
file_handler.setFormatter(formatter)

# add handler to logger
logger.addHandler(file_handler)


def requires_roles(*roles):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if current_user.role not in roles:
                logging.warning('SECURITY - Unauthorised access [%s %s %s %s]',
                                current_user.id,
                                current_user.email,
                                current_user.role,
                                request.remote_addr)
                return render_template('errors/403.html')
            return f(*args, **kwargs)

        return wrapped

    return wrapper


# HOME PAGE VIEW
@app.route('/')
def index():
    return render_template('main/index.html')


# BLUEPRINTS
# import blueprints
from users.views import users_blueprint
from admin.views import admin_blueprint
from lottery.views import lottery_blueprint

#
# # register blueprints with app
app.register_blueprint(users_blueprint)
app.register_blueprint(admin_blueprint)
app.register_blueprint(lottery_blueprint)

login_manager = LoginManager()
login_manager.login_view = 'users.login'
login_manager.init_app(app)

from models import User


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


# error handling
@app.errorhandler(400)
def bad_request_error(error):
    return render_template("errors/400.html"), 400


@app.errorhandler(403)
def forbidden_error(error):
    return render_template("errors/403.html"), 403


@app.errorhandler(404)
def not_found_error(error):
    return render_template("errors/404.html"), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template("errors/500.html"), 500


@app.errorhandler(503)
def unavailable_service_error(error):
    return render_template("errors/503.html"), 503


if __name__ == "__main__":
    app.run(ssl_context=('cert.pem', 'key.pem'))  # run HTTPS using certificates
