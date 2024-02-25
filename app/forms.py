from flask_wtf import FlaskForm
from wtforms import TextAreaField, StringField, PasswordField, FloatField, IntegerField, EmailField, SubmitField
from wtforms.validators import DataRequired, ValidationError, Email

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm = PasswordField('Confirm Password', validators=[DataRequired()])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Register')

    def validate_password(form, field):
        password = field.data
        special_characters = "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?"
        
        if len(password) < 8:
            raise ValidationError('Password must be at least 8 characters long.')
        
        if not any(char in special_characters for char in password):
            raise ValidationError('Password must contain at least one special character.')
        
        if not any(char.isupper() for char in password):
            raise ValidationError('Password must contain at least one capital letter.')