from flask import *
from app import app, models, db
from flask import render_template, flash, request, redirect, url_for, send_from_directory, session
from app.forms import LoginForm, RegisterForm, UploadForm, PaymentForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from datetime import datetime
from werkzeug.utils import secure_filename
import os
from datetime import datetime, timedelta
import stripe

app.config['SECRET_KEY'] = 'your_secret_key'

# Setting global secret key for Stripe API
stripe.api_key = "sk_test_51OlhekAu65yEau3hdrHvRwjs8vb8GM2NJnjLuJQYuGHeqgi5nYseoo8D2jIE4qKCvs7EPhzQIOJfQKQUej6SYD0600PGbY7CmA"

# Setting global dictionary for subscription products and their respective product ID's
SUBSCRIPTION_PRODUCTS_ID = {
    "Weekly": "price_1OnnSpAu65yEau3hfP2yBSke",
    "Monthly": "price_1OnnTpAu65yEau3hCLoW1nZP",
    "Yearly": "price_1OnpOoAu65yEau3hfk7nCPw1",
}

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
    subscription = models.Subscriptions.query.filter_by(user_id=current_user.id).first()
    if subscription:
        if subscription.payment_date < datetime.utcnow():
            if subscription.subscription_type == "Weekly":
                subscription.payment_date += timedelta(days=7)
            elif subscription.subscription_type == "Monthly":
                subscription.payment_date += timedelta(days=30)
            else:
                subscription.payment_date += timedelta(days=365)
            db.session.commit()
    return render_template('index.html')


# Need a page to land on to select what the user wants to pay
@app.route('/select_payment', methods=['GET', 'POST'])
def select_payment():
    form = PaymentForm(request.form)

    new_user_data = session.get('new_user')

    if not new_user_data:
        flash("User data not found. Please register first.")
        return redirect(url_for('register'))
    if form.validate_on_submit():
        payment_option = request.form.get('payment_option')
        session['payment_option'] = payment_option
        return redirect(url_for('payment'))  # Redirect to the payment route

    return render_template("/select_payment.html", form=form)


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    subscription = models.Subscriptions.query.filter_by(user_id=current_user.id).first()
    subscription_type = subscription.subscription_type
    return render_template('profile.html', subscription_type=subscription_type)

@app.route('/change_subscription', methods=['GET', 'POST'])
def change_subscription():
    form = PaymentForm()
    subscription = models.Subscriptions.query.filter_by(user_id=current_user.id).first()
    if subscription.subscription_type == "Weekly":
        next_payment_date =subscription.payment_date + timedelta(days=7)
        tariff = 'Weekly'
    elif subscription.subscription_type == "Monthly":
        next_payment_date =subscription.payment_date + timedelta(days=30)
        tariff = 'Monthly'
    else:
        next_payment_date =subscription.payment_date + timedelta(days=365)
        tariff = 'Yearly'
    next_payment_date = next_payment_date.strftime("%d/%m/%Y")
    if form.validate_on_submit():
        payment_option = request.form.get('payment_option')
        session['payment_option'] = payment_option
        return redirect(url_for('new_subscription'))  # Redirect to the payment route

    return render_template('change_subscription.html', next_payment_date=next_payment_date, form=form, tariff=tariff)

@app.route('/new_subscription', methods=['GET', 'POST'])
def new_subscription():
    try:
        # Retrieve form data from session
        payment_option = session.get('payment_option')
        if not payment_option:
            # Redirect user to select a payment option
            return redirect(url_for('change_subscription'))

        # Set up a Stripe checkout session with the uniquely selected product
        # Stripe's checkout session will take care of the card payment
        checkout_session = stripe.checkout.Session.create(
            line_items = [
                {
                    "price": SUBSCRIPTION_PRODUCTS_ID[payment_option],
                    "quantity": 1
                }
            ],
            mode="subscription",
            success_url = url_for('change_tariff', _external=True),
            cancel_url = url_for('change_subscription', _external=True)
        )

    except Exception as e:
        return str(e), 403
    
    return redirect(checkout_session.url, code=303)

@app.route('/change_tariff', methods=['GET', 'POST'])
def change_tariff():
    subscription = models.Subscriptions.query.filter_by(user_id=current_user.id).first()
    payment_option = session.get('payment_option')
    subscription.subscription_type = payment_option
    db.session.commit()
    return redirect(url_for('profile'))


# Redirect route for the Stripe payment screen
@app.route('/payment', methods=['GET', 'POST'])
def payment():
    try:
        new_user_data = session.get('new_user')

        if not new_user_data:
            flash("User data not found. Please register first.")
            return redirect(url_for('register'))
        
        # Retrieve form data from session
        payment_option = session.get('payment_option')
        if not payment_option:
            # Redirect user to select a payment option
            return redirect(url_for('select_payment'))

        # Set up a Stripe checkout session with the uniquely selected product
        # Stripe's checkout session will take care of the card payment
        checkout_session = stripe.checkout.Session.create(
            line_items = [
                {
                    "price": SUBSCRIPTION_PRODUCTS_ID[payment_option],
                    "quantity": 1
                }
            ],
            mode="subscription",
            success_url = url_for('login_new_user', _external=True),
            cancel_url = url_for('register', _external=True)
        )

    except Exception as e:
        return str(e), 403
    
    return redirect(checkout_session.url, code=303)

@app.route('/login_new_user')
def login_new_user():
    new_user_data = session.get('new_user')

    if not new_user_data:
        flash("User data not found. Please register first.")
        return redirect(url_for('register'))
    
    payment_option = session.get('payment_option')

    if not payment_option:
        flash("Payment option not found. Please select a payment option.")
        return redirect(url_for('select_payment'))
    
    user = models.User(
        username=new_user_data['username'],
        password=new_user_data['password'],
        firstname=new_user_data['firstname'],
        lastname=new_user_data['lastname'],
        email=new_user_data['email']
    )
    db.session.add(user)
    db.session.commit()
    subscription_details = models.Subscriptions(
        user_id=user.id,
        subscription_type=payment_option,
        payment_date=datetime.utcnow()
    )
    db.session.add(subscription_details)
    db.session.commit()
    login_user(user)
    flash('You have been registered and logged in successfully. Welcome ' + str(user.username) + '!')
    return redirect(url_for('index'))


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
            session['new_user'] = {
                'username': form.username.data,
                'password': hashed_password,
                'firstname': form.first_name.data,
                'lastname': form.last_name.data,
                'email': form.email.data
            }
            return render_template('select_payment.html', form=PaymentForm())
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

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    form = UploadForm()
    if request.method == 'POST' and form.validate_on_submit():
        file = form.file.data
        original_filename = secure_filename(file.filename)
        user_id = str(current_user.id)  # Get the user's ID
        upload_folder = os.path.join(app.root_path, 'static', 'uploads', user_id)  # Update the subfolder path

        if not os.path.exists(upload_folder):  # Create the subfolder if it doesn't exist
            os.makedirs(upload_folder)

        # Generate a unique filename by appending a timestamp
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        filename = f"{timestamp}_{original_filename}"

        file.save(os.path.join(upload_folder, filename))  # Save the file with the new unique name

        new_file = models.GPXFile(filename=filename, user_id=current_user.id)
        db.session.add(new_file)
        db.session.commit()

        flash('File successfully uploaded')
        return redirect(url_for('index'))
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(error, 'danger')
    return render_template('upload.html', form=form)

@app.route('/myfiles')
@login_required
def list_user_files():
    user_folder = os.path.join(app.root_path,'static','uploads',str(current_user.id))
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)
    files = os.listdir(user_folder)
    file_entries = models.GPXFile.query.filter_by(user_id=current_user.id).all()
    return render_template('list_files.html', files=files, file_entries=file_entries)

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    user_folder = os.path.join(app.root_path,'static','uploads',str(current_user.id))
    if not os.path.exists(os.path.join(user_folder, filename)):
        return 'File not found', 404
    return send_from_directory(user_folder, filename, as_attachment=True)

@app.route('/delete/<filename>')
@login_required
def delete_file(filename):
    user_folder = os.path.join(app.root_path,'static','uploads',str(current_user.id))
    if not os.path.exists(os.path.join(user_folder, filename)):
        return 'File not found', 404
    os.remove(os.path.join(user_folder, filename))
    db.session.query(models.GPXFile).filter(models.GPXFile.filename==filename).delete()
    db.session.commit()
    return redirect(url_for('list_user_files'))