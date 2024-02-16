from flask_wtf import FlaskForm
from wtforms import TextAreaField, StringField, PasswordField, FloatField, IntegerField, EmailField
from wtforms.validators import DataRequired, ValidationError, Email

class LoginForm(FlaskForm):
    username = TextAreaField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])


class RegisterForm(FlaskForm):
    username = TextAreaField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm = PasswordField('Confirm Password', validators=[DataRequired()])
    first_name = TextAreaField('First Name', validators=[DataRequired()])
    last_name = TextAreaField('Last Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email()])

    def validate_password(form, field):
        password = field.data
        special_characters = "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?"
        
        if len(password) < 8:
            raise ValidationError('Password must be at least 8 characters long.')
        
        if not any(char in special_characters for char in password):
            raise ValidationError('Password must contain at least one special character.')
        
        if not any(char.isupper() for char in password):
            raise ValidationError('Password must contain at least one capital letter.')