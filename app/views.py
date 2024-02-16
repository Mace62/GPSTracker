from flask import *
from app import app, models, db
from flask import render_template, flash, request, redirect, url_for
from app.forms import LoginForm, RegisterForm
from flask_login import LoginManager, login_user
from flask_login import logout_user, UserMixin, current_user
import bcrypt
from datetime import datetime

@app.route('/')
def index():
    return render_template('index.html')

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
            flash("Registered successfully.")

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
                flash("Logged in successfully!")
                return redirect(url_for('index'))
            else:
                flash("Incorrect username or password")
        except Exception as e:
            flash(f"Error: {e}")

    return render_template('login.html', form=form)