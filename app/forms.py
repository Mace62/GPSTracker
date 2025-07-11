from flask_wtf import FlaskForm
from wtforms import TextAreaField, StringField, PasswordField, FloatField, IntegerField, EmailField, SubmitField, HiddenField,SelectField
from flask_wtf.file import FileField, FileRequired
from wtforms import TextAreaField, StringField, PasswordField, FloatField, IntegerField, EmailField, SubmitField
from wtforms.validators import DataRequired, ValidationError, Email
from flask_wtf.file import FileAllowed

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
    submit = SubmitField('Next')

    def validate_password(form, field):
        password = field.data
        special_characters = "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?"
        
        if len(password) < 8:
            raise ValidationError('Password must be at least 8 characters long.')
        
        if not any(char in special_characters for char in password):
            raise ValidationError('Password must contain at least one special character.')
        
        if not any(char.isupper() for char in password):
            raise ValidationError('Password must contain at least one capital letter.')
        
class SearchForm(FlaskForm):
    query = StringField('Search')
    submit = SubmitField('Search')
    

class GroupCreationForm(FlaskForm):
    group_name = StringField('Group name', validators=[DataRequired()])
    selected_friends = HiddenField()  # Stores IDs of selected friends
    submit = SubmitField('Create Group')

class PMGCreationForm(FlaskForm):
    pmg_name = StringField('PMG name', validators=[DataRequired()])
    submit = SubmitField('Create PMG')

class PMGSelectionForm(FlaskForm):
    pmg = SelectField('Select a Group', choices=[('', '--- Select a PMG ---')], validate_choice=False)
    

class GroupSelectionForm(FlaskForm):
    group = SelectField('Select a Group', choices=[('', '--- Select a Group ---')], validate_choice=False)

# Payment form to get preferred payment option
class PaymentForm(FlaskForm):
    payment_option = HiddenField('selected_option')
    submit = SubmitField('Submit')
        
class UploadForm(FlaskForm):
    file = FileField('GPX File', validators=[
        FileRequired(),
        FileAllowed(['gpx'], 'Only GPX files can be uploaded!')
    ])


    submit = SubmitField('Upload')

class VerifyLoginForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Disable Account')

class ShareSelectionForm(FlaskForm):
    group = SelectField('Select a Group', validate_choice=False)
    submit = SubmitField('Share')

class AddSelectionForm(FlaskForm):
    pmg = SelectField('Select a PMG', validate_choice=False)
    submit = SubmitField('Add')