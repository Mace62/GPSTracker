from flask import *
from app import app, models, db
from flask import render_template, flash, request, redirect, url_for
from app.forms import LoginForm, RegisterForm
from flask_login import LoginManager, login_user
from flask_login import logout_user, UserMixin, current_user, login_required
import bcrypt
from datetime import datetime


app.config['SECRET_KEY'] = 'your_secret_key'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, username):
        self.username = username

    def get_id(self):
        return self.username


@login_manager.user_loader
def load_user(user_id):
    return models.User.query.filter_by(username=user_id).first()

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    else:
        return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        try:
            if models.User.query.filter_by(
                    username=form.username.data).first():
                flash("Username exists, try a different name")
                return render_template('register.html', form=form)
            
            if models.User.query.filter_by(
                    email=form.email.data).first():
                flash("Email exists, try a different email")
                return render_template('register.html', form=form)  

            if form.password.data != form.confirm.data:
                flash("Passwords do not match")
                return render_template('register.html', form=form)          

            # hash password and assign ID to new user
            num_ids = models.User.query.count()
            hashed_password = bcrypt.hashpw(
                form.password.data.encode('utf-8'), bcrypt.gensalt())
            new_user = models.User(id=num_ids+1,
                                       username=form.username.data,
                                       password=hashed_password,
                                       firstname=form.first_name.data,
                                       lastname=form.last_name.data,
                                       email=form.email.data)
            db.session.add(new_user)
            db.session.commit()
            flash("Registered and logged in successfully.")
            user_obj = User(new_user.username)
            login_user(user_obj)
            return redirect(url_for('index'))
        except Exception as e:
            flash(f"Error: {e}")

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    # if login button is clicked
    if form.validate_on_submit():
        try:
            user = models.User.query.filter_by(
                username=form.username.data).first()

            # hashes password input, compared to db
            if user and bcrypt.checkpw(
                    form.password.data.encode('utf-8'), user.password):
                if models.Admin.query.filter_by(user_id=user.id).first():
                    flash("Logged in as admin!")
                    user_obj = User(user.username)
                    login_user(user_obj)
                    return redirect(url_for('admin'))
                flash("Logged in successfully!")
                user_obj = User(user.username)
                login_user(user_obj)
                return redirect(url_for('index'))
            else:
                flash("Incorrect username or password")
        except Exception as e:
            flash(f"Error: {e}")

    return render_template('login.html', form=form)

@app.route('/admin')
@login_required
def admin():
    return render_template('admin.html')