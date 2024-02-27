from flask import *
from app import app, models, db
from flask import render_template, flash, request, redirect, url_for, jsonify
from app.forms import LoginForm, RegisterForm, EmptyForm
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from datetime import datetime
import os
import stripe

app.config['SECRET_KEY'] = 'your_secret_key'

# Setting global secret key for Stripe API
stripe.api_key = "sk_test_51OlhekAu65yEau3hdrHvRwjs8vb8GM2NJnjLuJQYuGHeqgi5nYseoo8D2jIE4qKCvs7EPhzQIOJfQKQUej6SYD0600PGbY7CmA"

bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'



@login_manager.user_loader
def load_user(user_id):
    return models.User.query.get(int(user_id))


@app.route('/')
@login_required
def index():
    return render_template('index.html')


#### Need a page to land on to select what the user wants to pay ####
@app.route('/select_payment', methods=['GET', 'POST'])
def select_payment():
    form = EmptyForm()
    return render_template("/select_payment.html", form=form)


####    THIS IS TEST CODE FOR THE STIRPE API IMPLEMENTATION     ####

@app.route('/payment', methods=['GET', 'POST'])
@login_required
def checkout_session():
    try:
        checkout_session = stripe.checkout.Session.create(
            line_items = [
                {
                    "price": "price_1OnnSpAu65yEau3hfP2yBSke",
                    "quantity": 1
                }
            ],
            mode="subscription",
            success_url = request.url + "/success.html",
            cancel_url = request.url + "/aborted.html"
        )

    except Exception as e:
        return str(e)
    
    return redirect(checkout_session.url, code=3030)


    # # Going to make a mock customer to use for the stripe payment 
    # customer = stripe.Customer.create(
    #     name = "Muhammad Kashif-Khan",
    #     email = "sc22makk@leeds.ac.uk"
    # )

    # # Creating a subscription object
    # # Will match the entities on the Stripe website using a price ID tag
    # subscription_weekly = stripe.Subscription.create(
    #     customer = customer.id,
    #     items = [
    #         {
    #             price = "price_1OnnSpAu65yEau3hfP2yBSke"
    #         }
    #     ]
    # )
    # stripe.
    # # try:
    # #     # Create a charge using the Stripe library
    # #     stripe.
    # #     charge = stripe.Charge.create(
    # #         amount=amount,
    # #         currency='gbp',
    # #         source=token,
    # #         description='Payment for your service'
    # #     )
    # #     # Handle successful payment
    # #     return 'Payment successful!'
    # # except stripe.error.CardError as e:
    # #     # Handle card errors
    # #     return str(e), 403


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        try:
            if models.User.query.filter_by(
                    username=form.username.data).first():
                flash("Username exists, try a different name.")
                return render_template('register.html', form=form)
            
            if models.User.query.filter_by(
                    email=form.email.data).first():
                flash("Email exists, try a different email.")
                return render_template('register.html', form=form)  

            if form.password.data != form.confirm.data:
                flash("Passwords do not match.")
                return render_template('register.html', form=form)          

            # hash password
            hashed_password = bcrypt.generate_password_hash(form.password.data)
            new_user = models.User(username=form.username.data,
                                       password=hashed_password,
                                       firstname=form.first_name.data,
                                       lastname=form.last_name.data,
                                       email=form.email.data)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            flash("Registered and logged in successfully.")
            return redirect(url_for('index'))
        except Exception as e:
            flash(f"Error: {e}")

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = models.User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if models.Admin.query.filter_by(user_id=user.id).first():
                login_user(user)
                flash('Logged in as admin')
                return redirect(url_for('admin'))   
            login_user(user)
            flash('Logged in successfully.')
            return redirect(url_for('index'))
        else:
            flash('Incorrect username or password. Please try again.', 'danger')

    return render_template('login.html', title="Login", form=form)

@app.route('/admin')
@login_required
def admin():
    return render_template('admin.html')
