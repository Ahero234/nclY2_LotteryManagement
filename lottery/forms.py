from flask_wtf import FlaskForm
from wtforms import IntegerField, SubmitField
from wtforms.validators import DataRequired, NumberRange


class DrawForm(FlaskForm):
    number1 = IntegerField(id='no1', validators=[DataRequired(message="Please fill in this field"),
                                                 NumberRange(min=1, max=60, message="Number must be between 1 and 60")])

    number2 = IntegerField(id='no2', validators=[DataRequired(message="Please fill in this field"),
                                                 NumberRange(min=1, max=60, message="Number must be between 1 and 60")])

    number3 = IntegerField(id='no3', validators=[DataRequired(message="Please fill in this field"),
                                                 NumberRange(min=1, max=60, message="Number must be between 1 and 60")])

    number4 = IntegerField(id='no4', validators=[DataRequired(message="Please fill in this field"),
                                                 NumberRange(min=1, max=60, message="Number must be between 1 and 60")])

    number5 = IntegerField(id='no5', validators=[DataRequired(message="Please fill in this field"),
                                                 NumberRange(min=1, max=60, message="Number must be between 1 and 60")])

    number6 = IntegerField(id='no6', validators=[DataRequired(message="Please fill in this field"),
                                                 NumberRange(min=1, max=60, message="Number must be between 1 and 60")])
    submit = SubmitField("Submit Draw")


def validate(self, **kwargs):
    standard_validators = FlaskForm.validate(self)
    if standard_validators:

        numbers = [self.number1.data, self.number2.data, self.number3.data, self.number4.data, self.number5.data,
                   self.number6.data]
        unique_nos = []
        for num in numbers:
            if num not in unique_nos:
                unique_nos.append(num)
                return True
            else:
                return False
