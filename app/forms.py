from flask_wtf import FlaskForm
from wtforms import TextAreaField, StringField, PasswordField, FloatField, IntegerField
from wtforms.validators import DataRequired, Length, NumberRange

class LoginForm(FlaskForm):
    username = TextAreaField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])


class RegisterForm(FlaskForm):
    username = TextAreaField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    first_name = TextAreaField('First Name', validators=[DataRequired()])
    last_name = TextAreaField('Last Name', validators=[DataRequired()])
    email = TextAreaField('Email', validators=[DataRequired()])