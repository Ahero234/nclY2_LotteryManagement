from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Email, ValidationError, Length, EqualTo
import re


# checks if first and last name doesn't contain any special characters
def char_check(form, field):
    invalid_chars = "*?!'^+%&/()=}][{$#@<>"
    for char in field.data:
        if char in invalid_chars:
            raise ValidationError(f"Character {char} is not allowed.")


# checks if phone number is in correct format
def phoneNum_check(form, field):
    p = re.compile(r"^\d{4}-\d{3}-\d{4}$")
    if not p.match(field.data):
        raise ValidationError("Phone number must be in the format: XXXX-XXX-XXXX")


# checks if password contains characters required
def validate_password(form, field):
    p = re.compile(r"(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[*?!'^+%&/()=}{$#@<>])")
    if not p.match(field.data):
        raise ValidationError("Password must contain at least 1 digit, at least 1 special character, at least 1 "
                              "lowercase and at least 1 uppercase word character")


# checks if date of birth is in correct format
def validate_dob(form, field):
    p = re.compile(r"^(0[1-9]|[12][0-9]|3[01])[- /.](0[1-9]|1[012])[- /.](19|20)\d\d$")
    if not p.match(field.data):
        raise ValidationError("Date of Birth must be in the format: DD/MM/YYYY")


# checks if postcode is in correct format
def validate_postcode(form, field):
    p = re.compile(r"^([A-Z][0-9]) ([0-9][A-Z]{2})|([A-Z][0-9]{2}) ([0-9][A-Z]{2})|([A-Z]{2}[0-9]) ([0-9][A-Z]{2})$")
    if not p.match(field.data):
        raise ValidationError(
            "Postcode must be in the format: XY YXX or XYY YXX or XXY YXX, where X is an uppercase letter and Y is a "
            "digit")


class RegisterForm(FlaskForm):
    email = StringField(validators=[DataRequired(message="Please fill in this field."), Email()])
    firstname = StringField(validators=[DataRequired(message="Please fill in this field."), char_check])
    lastname = StringField(validators=[DataRequired(message="Please fill in this field."), char_check])
    birthdate = StringField(validators=[DataRequired(message="Please fill in this field."), validate_dob])
    phone = StringField(validators=[DataRequired(message="Please fill in this field."), phoneNum_check])
    postcode = StringField(validators=[DataRequired(message="Please fill in this field."), validate_postcode])
    password = PasswordField(validators=[DataRequired(message="Please fill in this field."),
                                         Length(min=6, max=12), validate_password])
    confirm_password = PasswordField(validators=[DataRequired(message="Please fill in this field."),
                                                 EqualTo("password", message="Both passwords must match!")])
    submit = SubmitField()


class LoginForm(FlaskForm):
    email = StringField(validators=[DataRequired(), Email()])
    password = PasswordField(validators=[DataRequired()])
    pin = StringField(validators=[DataRequired()])
    postcode = StringField(validators=[DataRequired()])
    recaptcha = RecaptchaField()
    submit = SubmitField()


class PasswordForm(FlaskForm):
    current_password = PasswordField(id='password', validators=[DataRequired()])
    show_password = BooleanField('Show password', id='check')
    new_password = PasswordField(validators=[DataRequired(), Length(min=8, max=15, message="Must be between 8 and 15 characters in length"), validate_password])
    confirm_new_password = PasswordField(validators=[DataRequired(), EqualTo('new_password', message='Both new password fields must be equal')])
    submit = SubmitField('Change Password')
