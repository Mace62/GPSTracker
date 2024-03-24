from flask import *
from app import app, models, db
from flask import render_template, flash, request, redirect, url_for
from flask import send_from_directory, session
from app.forms import *
from app.models import *
from flask_wtf.file import FileField, FileRequired, FileAllowed
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, login_user, LoginManager, login_required
from flask_login import logout_user, current_user
from werkzeug.utils import secure_filename
import os
from datetime import datetime, timedelta
import stripe
from sqlalchemy import not_
import math
import folium
from geopy.distance import geodesic


stripe.api_key = "sk_test_51OlhekAu65yEau3hdrHvRwjs8vb8GM2NJnjLuJQYuGHeqgi5n"\
    + "Yseoo8D2jIE4qKCvs7EPhzQIOJfQKQUej6SYD0600PGbY7CmA"

# Setting dict for subscription products and their respective product ID's
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
    return User.query.get(int(user_id))


@app.route('/')
def landing():
    # Check if the user is already logged in
    if current_user.is_authenticated:
        user = User.query.filter_by(username=session.get('username')).first()
        admin = Admin.query.filter_by(user_id=user.id).first()
        if admin:
            return redirect(url_for('admin'))
        return redirect(url_for('homepage'))
    return render_template('landing.html')


@app.route('/homepage')
@login_required
def homepage():
    username = session.get('username')
    user = User.query.filter_by(username=username).first()
    user_subscription = Subscriptions.query.filter_by(user_id=user.id).first()

    # Check if the user needs to be locked out because they have unsubscribed
    if user:
        if (user_subscription
                and user_subscription.payment_date < datetime.utcnow()
                and user.has_paid is False):
            # Delete payment data and logout user
            db.session.delete(user_subscription)
            db.session.commit()
            return redirect(url_for("logout"))

        elif not user_subscription:
            return redirect(url_for("logout"))

    subscriptions = Subscriptions.query.all()
    num_subs = Subscriptions.query.count()
    # Loops to refresh the time to pay
    if subscriptions:
        for subscription in subscriptions:
            if subscription.payment_date < datetime.utcnow():
                if subscription.subscription_type == "Weekly":
                    subscription.payment_date += timedelta(days=7)
                elif subscription.subscription_type == "Monthly":
                    subscription.payment_date += timedelta(days=30)
                else:
                    subscription.payment_date += timedelta(days=365)
                db.session.commit()
    return render_template('homepage.html', username=username,
                           num_subs=num_subs, title='Home')


# Need a page to land on to select what the user wants to pay
@app.route('/select_payment', methods=['GET', 'POST'])
def select_payment():
    form = PaymentForm(request.form)

    new_user_data = session.get('new_user')
    username = session.get('username')

    if not (new_user_data or username):
        flash('You must log in to continue')
        return redirect(url_for('login'))

    if form.validate_on_submit():
        payment_option = request.form.get('payment_option')
        session['payment_option'] = payment_option
        return redirect(url_for('payment'))

    return render_template("/select_payment.html", form=form,
                           title="Select Payment")


@app.route('/change_subscription', methods=['GET', 'POST'])
@login_required
def change_subscription():
    form = PaymentForm()
    subscription = Subscriptions.query.filter_by(
        user_id=current_user.id).first()
    next_payment_date = subscription.payment_date.strftime("%Y-%m-%d")

    if form.validate_on_submit():
        payment_option = request.form.get('payment_option')
        session['payment_option'] = payment_option
        # Redirect to the payment route
        return redirect(url_for('new_subscription'))

    return render_template('change_subscription.html',
                           next_payment_date=next_payment_date, form=form,
                           title="Change Subscription")


@app.route('/cancel_subscription', methods=['GET', 'POST'])
@login_required
def cancel_subscription():
    name = session.get('username')
    form = VerifyLoginForm()
    user = User.query.filter_by(username=name).first()

    if user and user.has_paid is False:
        flash("You have already cancelled your subscription")
        return (redirect(url_for("homepage")))

    if form.validate_on_submit():
        # Check if the user exists and the password is correct
        if (user
                and bcrypt.check_password_hash(user.password,
                                               form.password.data)):
            user.has_paid = False
            db.session.commit()

            flash("Your account will be locked after the subscription has \
                  expired")
            return (redirect(url_for("homepage")))

        else:
            return (redirect(url_for("cancel_subscription")))

    return (render_template("cancel_subscription.html", form=form))


@app.route('/new_subscription', methods=['GET', 'POST'])
@login_required
def new_subscription():
    try:
        # Retrieve form data from session
        payment_option = session.get('payment_option')
        if not payment_option:
            # Redirect user to select a payment option
            return redirect(url_for('change_subscription'))

        # Set up a Stripe checkout session with the uniquely selected product
        checkout_session = stripe.checkout.Session.create(
            line_items=[
                {
                    "price": SUBSCRIPTION_PRODUCTS_ID[payment_option],
                    "quantity": 1
                }
            ],
            mode="subscription",
            success_url=url_for('change_tariff', _external=True),
            cancel_url=url_for('change_subscription', _external=True)
        )

        return redirect(checkout_session.url, code=303)

    except stripe.error.StripeError as e:
        flash('An error occurred while processing your payment. ' + e)
        return redirect(url_for('select_payment'), code=400)

    except Exception as e:
        flash('An unexpected error occurred. ' + e)
        return redirect(url_for('select_payment'), code=400)


@app.route('/change_tariff', methods=['GET', 'POST'])
@login_required
def change_tariff():
    # Retrieve the current user's subscription
    subscription = Subscriptions.query.filter_by(
        user_id=current_user.id).first()
    payment_option = session.get('payment_option')
    subscription.subscription_type = payment_option

    # Update the payment date based on the selected subscription type
    if subscription.subscription_type == "Weekly":
        subscription.payment_date += timedelta(days=7)
    elif subscription.subscription_type == "Monthly":
        subscription.payment_date += timedelta(days=30)
    else:
        subscription.payment_date += timedelta(days=365)
    db.session.commit()
    flash('Your subscription has been updated successfully.')
    return redirect(url_for('profile'))


# Redirect route for the Stripe payment screen
@app.route('/payment', methods=['GET', 'POST'])
def payment():
    try:
        new_user_data = session.get('new_user')
        username = session.get('username')

        if not (new_user_data or username):
            flash('You must log in to continue')
            return redirect(url_for('login'))

        # Retrieve form data from session
        payment_option = session.get('payment_option')
        if not payment_option:
            return redirect(url_for('select_payment'))

        # Set up a Stripe checkout session with the uniquely selected product
        checkout_session = stripe.checkout.Session.create(
            line_items=[
                {
                    "price": SUBSCRIPTION_PRODUCTS_ID[payment_option],
                    "quantity": 1
                }
            ],
            mode="subscription",
            success_url=url_for('login_new_user', _external=True),
            cancel_url=url_for('register', _external=True)
        )

        return redirect(checkout_session.url, code=303)

    except stripe.error.StripeError as e:
        flash('An error occurred while processing your payment. ' + e)
        return redirect(url_for('select_payment'), code=400)

    except Exception as e:
        flash('An unexpected error occurred. ' + e)
        return redirect(url_for('select_payment'), code=400)


@app.route('/login_new_user')
def login_new_user():
    new_user_data = session.get('new_user')
    payment_option = session.get('payment_option')

    # Search by database to check if the user already exists
    existing_user = User.query.filter(
        User.username == new_user_data['username']
    ).first()

    # print(existing_user.username)

    # if the user exists and user hasn't paid (i.e. returning user)
    if existing_user and existing_user.has_paid is False:
        existing_user.has_paid = True
        db.session.commit()
        user = existing_user

    elif not new_user_data:
        flash("User data not found. Please register first.")
        return redirect(url_for('register'))

    elif not payment_option:
        flash("Payment option not found. Please select a payment option.")
        return redirect(url_for('select_payment'))

    # If we are dealing with a new user
    else:
        user = User(
            username=new_user_data['username'],
            password=new_user_data['password'],
            firstname=new_user_data['firstname'],
            lastname=new_user_data['lastname'],
            email=new_user_data['email'],
            has_paid=True
        )

        db.session.add(user)
        db.session.commit()

    session['user_has_paid'] = user.has_paid

    session['username'] = user.username

    # Create a subscription record for the user
    if payment_option == "Weekly":
        next_payment = datetime.utcnow() + timedelta(days=7)
    elif payment_option == "Monthly":
        next_payment = datetime.utcnow() + timedelta(days=30)
    else:
        next_payment = datetime.utcnow() + timedelta(days=365)
    subscription_details = Subscriptions(
        user_id=user.id,
        subscription_type=payment_option,
        payment_date=next_payment
    )
    db.session.add(subscription_details)
    db.session.commit()
    login_user(user)
    if existing_user:
        flash(
            f'Welcome back {existing_user.username}. Thank you for \
                resubscribing to our services')
    else:
        flash(
            f'You have been registered and logged in successfully. \
                Welcome {str(user.username)}!')
    return redirect(url_for('homepage'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('landing'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        if Admin.query.filter_by(user_id=current_user.id).first():
            flash('You are already logged in as admin')
            return redirect(url_for('admin'))
        else:
            flash('You are already logged in')
            return redirect(url_for('homepage'))
    form = RegisterForm()
    create_admin()
    if form.validate_on_submit():
        try:
            if User.query.filter_by(
                    username=form.username.data).first():
                flash("Username exists, try a different name.")
                return render_template('register.html', form=form,
                                       title="Register")

            if User.query.filter_by(
                    email=form.email.data).first():
                flash("Email exists, try a different email.")
                return render_template('register.html', form=form,
                                       title="Register")

            if form.password.data != form.confirm.data:
                flash("Passwords do not match.")
                return render_template('register.html', form=form,
                                       title="Register")

            hashed_password = bcrypt.generate_password_hash(form.password.data)

            # Store the new user data in the session to be retrieved later
            session['new_user'] = {
                'username': form.username.data,
                'password': hashed_password,
                'firstname': form.first_name.data,
                'lastname': form.last_name.data,
                'email': form.email.data
            }
            return render_template('select_payment.html', form=PaymentForm(),
                                   title="Select Payment")
        except Exception as e:
            flash(f"Error: {e}")
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(error)

    return render_template('register.html', form=form, title="Register")


def create_admin():
    # Only create an admin when the database is empty
    if User.query.count() == 0:
        new_admin = User(username="admin",
                         password=bcrypt.generate_password_hash(
                             "Admin123!"), firstname="admin", lastname="admin",
                         email="admin@admin.com", has_paid=True)
        db.session.add(new_admin)
        db.session.commit()
        admin = Admin(user_id=new_admin.id)
        db.session.add(admin)
        db.session.commit()


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if Admin.query.filter_by(user_id=current_user.id).first():
            flash('You are already logged in as admin')
            return redirect(url_for('admin'))
        else:
            flash('You are already logged in')
            return redirect(url_for('homepage'))
    form = LoginForm()
    create_admin()
    if form.validate_on_submit():
        # Check if the user exists and the password is correct
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password,
                                               form.password.data):
            session['username'] = form.username.data

            if Admin.query.filter_by(user_id=user.id).first():
                login_user(user)
                flash('Logged in as admin')
                return redirect(url_for('admin'))

            # Check if the user has paid
            if not Subscriptions.query.filter_by(user_id=user.id).first():
                return redirect(url_for('select_payment'), code=302)

            login_user(user)
            flash('Logged in successfully.')
            return redirect(url_for('homepage'))
        else:
            flash('Incorrect username or password. Please try again.',
                  'danger')

    return render_template('login.html', title="Login", form=form)


@app.route('/admin')
@login_required
def admin():
    if not Admin.query.filter_by(user_id=current_user.id).first():
        flash('You are not an admin!')
        return redirect(url_for('homepage'))
    num_users = Subscriptions.query.count()
    future_revenue_data = calculate_future_revenue()

    total_revenue = round(sum(future_revenue_data), 2)
    return render_template('admin.html', num_users=num_users,
                           total_revenue=total_revenue, title='Administration')


def get_friends_choices(user_id):
    sent_friend_requests = db.session.query(FriendRequest.receiver_id).filter(
        FriendRequest.sender_id == user_id,
        FriendRequest.status == 'accepted').all()
    received_friend_requests = db.session.query(
        FriendRequest.sender_id).filter(
        FriendRequest.receiver_id == user_id,
        FriendRequest.status == 'accepted').all()

    friend_ids = [user_id for (
        user_id,) in sent_friend_requests + received_friend_requests]

    friends = User.query.filter(
        User.id.in_(friend_ids)).all() if friend_ids else []

    return [(friend.id, friend.username) for friend in friends]


def perform_user_search(query, current_user):
    results = []
    follow_status = {}
    if query:
        results = User.query.filter(
            User.username.ilike(f'%{query}%'),
            User.id != current_user.id,
            User.username != 'admin'
        ).all()

        for user in results:
            # Check for requests sent by the current user
            sent_request = FriendRequest.query.filter_by(
                sender_id=current_user.id, receiver_id=user.id).first()
            if sent_request:
                follow_status[user.id] = {
                    'status': sent_request.status,
                    'request_id': sent_request.id}

            else:
                # Check for requests received by the current user
                received_request = FriendRequest.query.filter_by(
                    sender_id=user.id, receiver_id=current_user.id).first()
                if received_request:
                    if (received_request.status == "pending"):
                        follow_status[user.id] = {
                            'status': received_request.status + "_received",
                            'request_id': received_request.id}

                    else:
                        follow_status[user.id] = {
                            'status': received_request.status,
                            'request_id': received_request.id}

        for user in results:
            if user.id not in follow_status:
                follow_status[user.id] = {
                    'status': 'no_action', 'request_id': None}
    return results, follow_status


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    subscription = Subscriptions.query.filter_by(
        user_id=current_user.id).first()
    subscription_type = subscription.subscription_type

    query = request.args.get('q')
    form = SearchForm()
    received_requests = current_user.received_requests.filter_by(
        status='pending').all()
    # Fetch received friend requests
    friend_ids = [friend_id for friend_id,
                  _ in get_friends_choices(current_user.id)]
    friends = User.query.filter(
        User.id.in_(friend_ids)).all() if friend_ids else []
    results = []
    follow_status = {}

    if query:
        results, follow_status = perform_user_search(query, current_user)
        # Update follow_status for each user based on friendship

    return render_template('profile.html', form=form, query=query,
                           results=results, user=current_user,
                           follow_status=follow_status,
                           received_requests=received_requests,
                           friends=friends,
                           subscription_type=subscription_type,
                           title='Profile')


@app.route('/send_friend_request/<username>', methods=['POST'])
@login_required
def send_friend_request(username):
    user_to_request = User.query.filter_by(
        username=username).first_or_404()

    # Check if the user is trying to send a friend request to themselves
    if current_user.id == user_to_request.id:
        flash("You cannot send a friend request to yourself.", "danger")
        return redirect(url_for('profile', username=username))

    # Check if friend request exists or if they are already friends
    existing_request = FriendRequest.query.filter(
        ((FriendRequest.sender_id == current_user.id) & (
            FriendRequest.receiver_id == user_to_request.id)) |
        ((FriendRequest.receiver_id == current_user.id) &
         (FriendRequest.sender_id == user_to_request.id))
    ).first()

    if existing_request:
        if existing_request.status == 'pending':
            flash("Friend request already sent.", "info")
        elif existing_request.status == 'accepted':
            flash("You are already friends.", "info")
    else:
        # If no existing request, create a new friend request
        new_request = FriendRequest(
            sender_id=current_user.id, receiver_id=user_to_request.id,
            status='pending')
        db.session.add(new_request)
        db.session.commit()
        flash(f"Friend request sent to {username}.", "success")

    return redirect(url_for('profile', username=username))


@app.route('/deny_friend_request/<int:request_id>', methods=['POST'])
@login_required
def deny_friend_request(request_id):
    request = FriendRequest.query.get_or_404(request_id)
    if request.receiver_id == current_user.id:
        # Delete the friend request instead of changing its status
        db.session.delete(request)
        db.session.commit()
        flash('Friend request denied.', 'success')
    else:
        flash('Unauthorized action.', 'danger')
    return redirect(url_for('profile'))


@app.route('/accept_friend_request/<int:request_id>', methods=['POST'])
@login_required
def accept_friend_request(request_id):

    request = FriendRequest.query.get_or_404(request_id)

    # Now, using the friend request, fetch the sender and receiver
    sender = User.query.get(request.sender_id)
    receiver = User.query.get(request.receiver_id)

    if request.receiver_id == current_user.id:
        request.status = 'accepted'
        db.session.commit()
        flash('Friend request accepted.', 'success')
    else:
        flash('Unauthorized action.', 'danger')

    return redirect(url_for('profile'))


@app.route('/remove_friend/<int:friend_id>', methods=['POST'])
@login_required
def remove_friend(friend_id):
    # Assuming 'friend_id' is the user ID of the friend to be removed

    # Check if the user has friend request with given friend_id that's accepted
    friend_request = FriendRequest.query.filter(
        FriendRequest.status == 'accepted',
        ((FriendRequest.sender_id == current_user.id) & (
            FriendRequest.receiver_id == friend_id)) |
        ((FriendRequest.sender_id == friend_id) &
         (FriendRequest.receiver_id == current_user.id))
    ).first()

    if not friend_request:
        flash("No friend connection found.", "danger")
        return redirect(url_for('profile'))

    db.session.delete(friend_request)

    db.session.commit()
    flash('Friend removed successfully.', 'success')
    return redirect(url_for('profile'))


@app.route('/cancel_friend_request/<int:request_id>', methods=['POST'])
@login_required
def cancel_friend_request(request_id):
    # query to check if the current user is the sender of the friend request
    friend_request = FriendRequest.query.get_or_404(request_id)
    if (friend_request.sender_id == current_user.id
            and friend_request.status == 'pending'):
        db.session.delete(friend_request)
        db.session.commit()
        flash('Friend request canceled.', 'success')
    else:
        flash('Unauthorized action or request not found.', 'danger')
    return redirect(url_for('profile'))


def create_group(user_ids, group_name):
    # Create a new group instance
    new_group = Group(name=group_name)
    db.session.add(new_group)
    db.session.flush()

    # Add the current user and selected friends to the group
    for user_id in user_ids:
        # Ensure no attempt to add non-existent users
        if User.query.get(user_id):
            new_group_member = GroupMember(
                group_id=new_group.id, user_id=user_id)
            db.session.add(new_group_member)

    db.session.commit()
    return new_group


@app.route('/share/<filename>', methods=['GET', 'POST'])
@login_required
def share(filename):
    selection_form = ShareSelectionForm()
    user_groups = GroupMember.query.filter_by(
        user_id=current_user.id).all()
    # Extract group IDs for querying Group details
    group_ids = [membership.group_id for membership in user_groups]
    groups = Group.query.filter(
        Group.id.in_(group_ids)).all() if group_ids else []
    selection_form.group.choices = [
        ('', '--- Select a Group ---')] + [(g.id, g.name) for g in groups]

    if selection_form.validate_on_submit():
        selected_group_id = selection_form.group.data
        selected_group = Group.query.get(selected_group_id)
        if selected_group:
            # Check if the file is already shared with the selected group
            gpx_file = GPXFileData.query.filter_by(filename=filename).first()
            if not (SharedGPXFile.query.filter_by(file_id=gpx_file.id,
                                                  group_id=selected_group_id)
                    .first()):
                new_share = SharedGPXFile(file_id=gpx_file.id,
                                          group_id=selected_group_id)
                db.session.add(new_share)
                db.session.commit()
                flash('File shared successfully.', 'success')
            else:
                flash('File already shared with selected group.', 'error')
            return redirect(url_for('list_user_files'))
        else:
            flash('Invalid group selected.', 'error')
    return render_template('share.html', selection_form=selection_form,
                           filename=filename, title="Share")


@app.route('/add/<filename>', methods=['GET', 'POST'])
@login_required
def add(filename):
    selection_form = AddSelectionForm()
    user_PMGS = PMG.query.filter_by(
        user_id=current_user.id).all()
    # Extract group IDs for querying Group details
    pmg_ids = [pmg_info.group_id for pmg_info in user_PMGS]

    groups = Group.query.filter(
        Group.id.in_(pmg_ids)).all() if pmg_ids else []
    selection_form.pmg.choices = [
        ('', '--- Select a PMG ---')] + [(g.id, g.name) for g in groups]

    if selection_form.validate_on_submit():
        selected_group_id = selection_form.pmg.data
        selected_group = Group.query.get(selected_group_id)
        if selected_group:
            gpx_file = GPXFileData.query.filter_by(filename=filename).first()
            if not (SharedGPXFile.query.filter_by(file_id=gpx_file.id,
                                                  group_id=selected_group_id)
                    .first()):
                new_share = SharedGPXFile(
                    file_id=gpx_file.id, group_id=selected_group_id)
                db.session.add(new_share)
                db.session.commit()
                flash('File Added successfully.', 'success')
            else:
                flash('File already shared with PMG.', 'error')
            return redirect(url_for('list_user_files'))
        else:
            flash('Invalid PMG selected.', 'error')
    return render_template('add.html', selection_form=selection_form,
                           filename=filename, title="Add")


@app.route('/group', defaults={'group_id': None}, methods=['GET', 'POST'])
@app.route('/group/<group_id>', methods=['GET', 'POST'])
@login_required
def group(group_id):
    creation_form = GroupCreationForm()
    selection_form = GroupSelectionForm()
    user_groups = GroupMember.query.filter_by(
        user_id=current_user.id).all()
    # Extract group IDs for querying Group details
    group_ids = [membership.group_id for membership in user_groups]
    groups = Group.query.filter(
        Group.id.in_(group_ids)).all() if group_ids else []
    selection_form.group.choices = [
        ('', '--- Select a Group ---')] + [(g.id, g.name) for g in groups]

    num_groups = GroupMember.query.filter_by(
        user_id=current_user.id).count()

    if creation_form.validate_on_submit():
        # Parse form data to get selected friend IDs and include current userID
        group_user_ids = request.form.get('selected_friends').split(',')
        group_user_ids.append(str(current_user.id))

        # Extracted name of the group from the form
        group_name = creation_form.group_name.data

        # list of all user IDs (the current user and selected friends)
        user_ids = [current_user.id] + \
            [int(uid) for uid in group_user_ids if uid.isdigit()]

        # Check if any user in the user_ids list has group with given name
        existing_group = Group.query.join(GroupMember).filter(
            Group.name == group_name,
            GroupMember.user_id.in_(user_ids)).first()

        if existing_group:
            # If group exists, do not proceed with creating the new group
            flash(
                'A group with this name already exists within your selected \
                    group of friends.', 'error')
        else:
            new_group = create_group(group_user_ids, group_name)
            flash('Group created successfully.', 'success')
            return redirect(url_for('group'))

    friends_choices = get_friends_choices(current_user.id)

    if group_id is not None and group_id != '':
        selection_form.group.data = group_id
    else:
        # Logic for rendering the default /group page...
        selection_form.group.data = ''

    if group_id:
        selected_group = Group.query.get(group_id)
        if selected_group:
            display_group_name = selected_group.name
        else:
            display_group_name = '-- Select a Group --'
    else:
        display_group_name = '-- Select a Group --'

    return render_template('group.html', creation_form=creation_form,
                           groups=groups, friends_choices=friends_choices,
                           selection_form=selection_form,
                           display_group_name=display_group_name,
                           num_groups=num_groups, title='Groups')


@app.route('/pmgs', defaults={'pmg_id': None}, methods=['GET', 'POST'])
@app.route('/pmgs/<pmg_id>', methods=['GET', 'POST'])
@login_required
def pmgs(pmg_id):
    creation_form = PMGCreationForm()
    selection_form = PMGSelectionForm()

    user_PMGS = PMG.query.filter_by(
        user_id=current_user.id).all()
    # Extract group IDs for querying Group details
    pmg_ids = [pmg_info.group_id for pmg_info in user_PMGS]

    groups = Group.query.filter(
        Group.id.in_(pmg_ids)).all() if pmg_ids else []
    selection_form.pmg.choices = [
        ('', '--- Select a PMG ---')] + [(g.id, g.name) for g in groups]

    num_groups = GroupMember.query.filter_by(
        user_id=current_user.id).count()

    if creation_form.validate_on_submit():
        # Extracted name of the group from the form
        pmg_name = creation_form.pmg_name.data

        # Query to check if any user in user_ids list has group with given name
        existing_group = None

        if existing_group:
            # If such group exists, do not proceed with creating the new group
            flash(
                'A group with this name already exists within your selected \
                    group of friends.', 'error')
        else:
            # If the name is unique, proceed with group creation
            new_pmg_group = Group(name=pmg_name)
            db.session.add(new_pmg_group)
            db.session.commit()
            new_pmg = PMG(user_id=current_user.id, group_id=new_pmg_group.id)
            db.session.add(new_pmg)
            db.session.commit()
            flash('PMG created successfully.', 'success')
            return redirect(url_for('pmgs'))  # Redirect as appropriate

    if pmg_id is not None and pmg_id != '':
        selection_form.pmg.data = pmg_id
    else:
        # Logic for rendering the default /group page...
        selection_form.pmg.data = ''

    if pmg_id:
        selected_group = Group.query.get(pmg_id)
        if selected_group:
            display_group_name = selected_group.name
        else:
            display_group_name = '-- Select a Group --'
    else:
        display_group_name = '-- Select a Group --'

    return render_template('pmgs.html', creation_form=creation_form,
                           groups=groups, selection_form=selection_form,
                           display_group_name=display_group_name,
                           num_groups=num_groups, title='PMGs')


@app.route('/all_users')
@login_required
def all_users():
    if not Admin.query.filter_by(user_id=current_user.id).first():
        flash('You are not an admin!')
        return redirect(url_for('homepage'))
    admin_user_ids = [admin.user_id for admin in Admin.query.all()]

    # Get all users who are not admins
    non_admin_users = User.query.filter(
        not_(User.id.in_(admin_user_ids))).all()

    user_ids = [user.id for user in non_admin_users]

    user_subscriptions = Subscriptions.query.filter(
        Subscriptions.user_id.in_(user_ids)).all()

    return render_template('all_users.html', users=non_admin_users,
                           subscriptions=user_subscriptions, title='All Users')


def calculate_future_revenue():
    data = [0] * 53
    current_date = datetime.utcnow()

    # Calculate the end date for the next year
    end_date = current_date + timedelta(days=365)

    for subscription in Subscriptions.query.all():
        # Skip subscriptions that have already been renewed in the next year
        if subscription.payment_date >= end_date:
            continue

        # Get the week number of the payment date
        payment_week = subscription.payment_date
        payment_week_number = payment_week.isocalendar()[1]
        weeks_away = payment_week_number - current_date.isocalendar()[1]
        if subscription.subscription_type == "Weekly":
            # Add revenue to payment week and every week after up to week 52
            for i in range(weeks_away, 53):
                data[i] += 1.99
        elif subscription.subscription_type == "Monthly":
            for i in range(weeks_away, 53, 4):
                data[i] += 6.99
        else:
            data[weeks_away] += 79.99

    return data


@app.route('/future_revenue', methods=['GET', 'POST'])
@login_required
def future_revenue():
    if not Admin.query.filter_by(user_id=current_user.id).first():
        flash('You are not an admin!')
        return redirect(url_for('homepage'))

    # Initialize graph data
    graph_data = {
        'labels': [],
        'data': []
    }

    # Generate labels for weeks 1 to 52
    for week_number in range(1, 53):
        week_label = f"Week {week_number}"
        graph_data['labels'].append(week_label)

    graph_data['data'] = calculate_future_revenue()

    return render_template('future_revenue.html', graph_data=graph_data,
                           title='Future Revenue')


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    form = UploadForm()
    if request.method == 'POST' and form.validate_on_submit():
        file = form.file.data
        original_filename = secure_filename(file.filename)
        user_id = str(current_user.id)

        # Update the subfolder path
        upload_folder = os.path.join(
            app.root_path, 'static', 'uploads', user_id)

        # Create the subfolder if it doesn't exist
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)

        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        filename = f"{timestamp}_{original_filename}"

        # Save the file with the new unique name
        file.save(os.path.join(upload_folder, filename))

        gpx_file = GPXFile(
            name=filename, filepath=os.path.join(upload_folder, filename))
        gpx_file.save_to_db(current_user.id)

        flash('File successfully uploaded')

        return redirect(url_for('view', filename=filename))
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(error, 'danger')

    return render_template('upload.html', form=form, title='Upload File')


@app.route('/myfiles')
@login_required
def list_user_files():
    user_folder = os.path.join(
        app.root_path, 'static', 'uploads', str(current_user.id))

    # Create the user folder if it doesn't exist
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)
    files = os.listdir(user_folder)
    file_entries = GPXFileData.query.filter_by(
        user_id=current_user.id).all()
    return render_template('list_files.html', files=files,
                           file_entries=file_entries, title='My Journeys')


@app.route('/generate_map/<filename>')
@login_required
def generate_map(filename):
    user_folder = os.path.join(
        app.root_path, 'static', 'uploads', str(current_user.id))
    if not os.path.exists(os.path.join(user_folder, filename)):
        return 'File not found', 404
    gpx_file = GPXFileData.query.filter_by(filename=filename).first()

    waypoints = GPXWaypoint.query.filter_by(
        file_id=gpx_file.id).all()
    tracks = GPXTrack.query.filter_by(file_id=gpx_file.id).all()
    track_points = GPXTrackPoint.query.join(GPXTrack).filter(
        GPXTrack.file_id == gpx_file.id).all()

    # Grab lat and long coords to initialise the map
    # Set default coordinates if no track points or waypoints are available
    map_lat = 0.0
    map_long = 0.0
    if track_points:
        map_lat = track_points[0].latitude
        map_long = track_points[0].longitude
    elif waypoints:
        map_lat = waypoints[0].latitude
        map_long = waypoints[0].longitude

    run_map = folium.Map(
        location=[map_lat, map_long], tiles=None, zoom_start=12)

    # add Openstreetmap layer
    folium.TileLayer('openstreetmap', name='OpenStreet Map').add_to(run_map)

    # add feature group for Waypoints
    fg_waypoints = folium.FeatureGroup(name='Waypoints').add_to(run_map)

    # iterate over waypoints and create a marker for each
    for waypoint in waypoints:
        folium.Marker(
            location=[waypoint.latitude, waypoint.longitude],
            tooltip=waypoint.name,
            icon=folium.Icon(color='red')
        ).add_to(fg_waypoints)

    colors = ["blue", "red", "green", "orange",
              "purple", "yellow", "pink", "brown", "gray"]
    # create a feature group for tracks
    stats = {}
    elevation_data = []
    if tracks:
        for i, track in enumerate(tracks):
            fg_tracks = folium.FeatureGroup(name=track.name).add_to(run_map)
            track_points = GPXTrackPoint.query.filter_by(
                track_id=track.id).all()

            # create a list of coordinates for the trackpoints
            track_coords = [[point.latitude, point.longitude]
                            for point in track_points]
            # create a polyline with a different color for each track
            folium.PolyLine(track_coords, color=colors[i % len(colors)],
                            weight=4.5, opacity=1,
                            tooltip=track.name).add_to(fg_tracks)

            stats[track.name] = 'STATS'

            # Calculate total distance for this track
            total_distance = total_distance_for_gpx(track_points)
            stats[f"Total distance  {track.name}"] = "{:.2f} km".format(
                total_distance)

            # Calculate total time for this track
            total_time = total_time_for_gpx(track_points)
            stats[f"Total time  {track.name}"] = "{} hrs".format(total_time)

            # Calculate average speed for this track
            average_speed = average_speed_for_gpx(track_points)
            stats[f"Average Speed  {track.name}"] = "{:.2f} km/h".format(
                average_speed)

            # Calculate total elevation gain for this track
            total_elevation_gain = 0
            previous_elevation = track_points[0].elevation
            for point in track_points:
                if (point.elevation is not None
                        and previous_elevation is not None):
                    if point.elevation > previous_elevation:
                        total_elevation_gain += (point.elevation
                                                 - previous_elevation)
                previous_elevation = (point.elevation
                                      if point.elevation is not None
                                      else previous_elevation)

            stats[f"Total elevation gain  {track.name}"] = "{:.2f} ft".format(
                total_elevation_gain)

            # Calculate elevation data
            elevation_data.append({
                'name': track.name,
                'elevation': [point.elevation for point in track_points]
            })

    # add legend in top right corner
    run_map.add_child(folium.LayerControl(
        position='topright', collapsed=False, autoZIndex=True))

    map_file = f'{filename}_map.html'
    run_map.save(os.path.join(user_folder, map_file))

    # Read the generated HTML file and modify the size of the map container
    with open(os.path.join(user_folder, map_file), 'r') as f:
        html_content = f.read()

    # Modify the size of the map container div
    modified_html_content = html_content.replace(
        'class="folium-map"', 'class="folium-map" style="width: 45%; \
            height: 450px; border: 5px solid black;top: 10.0%; left: 5%"')

    # Save the modified HTML content back to the file
    with open(os.path.join(user_folder, map_file), 'w') as f:
        f.write(modified_html_content)

    map_file = f'{filename}_map.html'
    run_map.save(os.path.join(user_folder, map_file))

    # Redirect to the route that will serve the map
    return stats, elevation_data


@app.route('/generate_group_map/<group_id>')
@login_required
def generate_group_map(group_id):
    group_folder = os.path.join(
        app.root_path, 'static', 'group')
    if not os.path.exists(group_folder):
        os.makedirs(group_folder)

    file_ids = SharedGPXFile.query.filter_by(group_id=group_id).all()

    gpx_files = GPXFileData.query.filter(
        GPXFileData.id.in_([file_id.file_id for file_id in file_ids])).all()

    run_map = folium.Map(
        location=[0, 0], tiles=None, zoom_start=12)

    # add Openstreetmap layer
    folium.TileLayer('openstreetmap', name='OpenStreet Map').add_to(run_map)
    # add feature group for Waypoints
    fg_waypoints = folium.FeatureGroup(name='Waypoints').add_to(run_map)

    colour_counter = 0
    for gpx_file in gpx_files:
        waypoints = GPXWaypoint.query.filter_by(file_id=gpx_file.id).all()
        tracks = GPXTrack.query.filter_by(file_id=gpx_file.id).all()
        track_points = GPXTrackPoint.query.join(GPXTrack).filter(
            GPXTrack.file_id == gpx_file.id).all()
        owner_name = User.query.get(gpx_file.user_id).username

        # Grab lat and long coords to initialise the map
        # Set default coordinates if no track points or waypoints are available
        map_lat = 0.0
        map_long = 0.0
        if track_points:
            map_lat = track_points[0].latitude
            map_long = track_points[0].longitude
        elif waypoints:
            map_lat = waypoints[0].latitude
            map_long = waypoints[0].longitude

        run_map.location = [map_lat, map_long]

        colors = ["blue", "red", "green", "orange", "purple", "yellow", "pink",
                  "brown", "gray"]

        if waypoints:

            # iterate over waypoints and create a marker for each
            for waypoint in waypoints:
                folium.Marker(
                    location=[waypoint.latitude, waypoint.longitude],
                    tooltip=(owner_name+": "+waypoint.name),
                    icon=folium.Icon(color='red')
                ).add_to(fg_waypoints)
        # create a feature group for tracks
        if tracks:
            for i, track in enumerate(tracks):
                fg_tracks = folium.FeatureGroup(
                    name=track.name).add_to(run_map)
                track_points = GPXTrackPoint.query.filter_by(
                    track_id=track.id).all()

                # create a list of coordinates for the trackpoints
                track_coords = [[point.latitude, point.longitude]
                                for point in track_points]
                # create a polyline with a different color for each track
                folium.PolyLine(track_coords,
                                color=colors[colour_counter % len(colors)],
                                weight=4.5, opacity=1,
                                tooltip=(owner_name+": "+track.name)).add_to(fg_tracks)

            colour_counter += 1
            waypoints = None
            tracks = None

    run_map.add_child(folium.LayerControl(
        position='topright', collapsed=False, autoZIndex=True))

    map_file = f'{group_id}_map.html'
    run_map.save(os.path.join(group_folder, map_file))

    # Read the generated HTML file and modify the size of the map container
    with open(os.path.join(group_folder, map_file), 'r') as f:
        html_content = f.read()

    # Modify the size of the map container div
    modified_html_content = html_content.replace(
        'class="folium-map"', 'class="folium-map" style="width: 45%; \
            height: 450px; border: 5px solid black;top: 10.0%; left: 5%"')

    # Save the modified HTML content back to the file
    with open(os.path.join(group_folder, map_file), 'w') as f:
        f.write(modified_html_content)

    map_file = f'{group_id}_map.html'
    run_map.save(os.path.join(group_folder, map_file))


@app.route('/check_map_status/<filename>')
@login_required
def check_map_status(filename):
    # Check if the map file exists
    user_folder = os.path.join(
        app.root_path, 'static', 'uploads', str(current_user.id))
    map_file = f'{filename}_map.html'
    map_ready = os.path.exists(os.path.join(user_folder, map_file))
    return jsonify({'map_ready': map_ready})


@app.route('/check_group_map_status/<filename>')
@login_required
def check_group_map_status(filename):
    group_folder = os.path.join(
        app.root_path, 'static', 'group')
    map_file = f'{filename}_map.html'
    map_ready = os.path.exists(os.path.join(group_folder, map_file))
    return jsonify({'map_ready': map_ready})


@app.route('/serve_map/<filename>')
@login_required
def serve_map(filename):
    # Serve the generated map file
    user_folder = os.path.join(
        app.root_path, 'static', 'uploads', str(current_user.id))
    file_path = os.path.join(user_folder, filename)
    if not os.path.exists(file_path):
        return 'Map file not found', 404

    def generate():
        with open(file_path, "rb") as f:
            yield from f

    return Response(generate(), mimetype='text/html')


@app.route('/serve_group_map/<filename>')
@login_required
def serve_group_map(filename):
    group_folder = os.path.join(
        app.root_path, 'static', 'group')
    file_path = os.path.join(group_folder, filename)
    if not os.path.exists(file_path):
        return 'Map file not found', 404

    def generate():
        with open(file_path, "rb") as f:
            yield from f

    return Response(generate(), mimetype='text/html')


@app.route('/view/<filename>')
@login_required
def view(filename):
    # Generate the map and display it
    stats, elevation_data = generate_map(filename)
    user_folder = os.path.join(
        app.root_path, 'static', 'uploads', str(current_user.id))
    map_file = f'{filename}_map.html'
    map_url = url_for('serve_map', filename=map_file)
    return render_template('view_map.html', map_url=map_url, filename=filename,
                           stats=stats, elevation_data=elevation_data,
                           title='View Map')


@app.route('/viewgroup/<group_id>')
@login_required
def viewgroup(group_id):
    # check to see if user is part of group
    if not GroupMember.query.filter_by(user_id=current_user.id,
                                       group_id=group_id).first():
        if not PMG.query.filter_by(user_id=current_user.id,
                                   group_id=group_id).first():
            flash('You are not part of this group!')
            return redirect(url_for('profile'))
    generate_group_map(group_id)
    map_file = f'{group_id}_map.html'
    map_url = url_for('serve_group_map', filename=map_file)
    group_name = Group.query.get(group_id).name
    is_pmg = False
    is_pmg = PMG.query.filter_by(user_id=current_user.id,
                                 group_id=group_id).first() is not None
    return render_template('view_group_map.html', map_url=map_url,
                           group_name=group_name, group_id=group_id,
                           is_pmg=is_pmg)


@app.route('/download/<filename>')
@login_required
def download_file(filename):
    # Serve the file for download
    user_folder = os.path.join(
        app.root_path, 'static', 'uploads', str(current_user.id))
    if not os.path.exists(os.path.join(user_folder, filename)):
        return 'File not found', 404
    return send_from_directory(user_folder, filename, as_attachment=True)


@app.route('/delete/<filename>')
@login_required
def delete_file(filename):
    # Delete the file and its database entry
    user_folder = os.path.join(
        app.root_path, 'static', 'uploads', str(current_user.id))
    if not os.path.exists(os.path.join(user_folder, filename)):
        return 'File not found', 404
    os.remove(os.path.join(user_folder, filename))
    db.session.query(GPXFileData).filter(
        GPXFileData.filename == filename).delete()
    db.session.commit()
    return redirect(url_for('list_user_files'))


def calculate_distance(lat1, long1, lat2, long2):
    R = 6371  # Radius of the Earth in kilometers
    lat1_rad = math.radians(lat1)
    long1_rad = math.radians(long1)
    lat2_rad = math.radians(lat2)
    long2_rad = math.radians(long2)

    delta_lat = lat2_rad - lat1_rad
    delta_long = long2_rad - long1_rad

    a = math.sin(delta_lat/2)**2 + math.cos(lat1_rad) * \
        math.cos(lat2_rad) * math.sin(delta_long/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

    distance = R * c  # Distance in kilometers
    return distance


# Function to calculate total distance for all points in GPX file
def total_distance_for_gpx(gpx_points):
    total_distance = 0
    for i in range(len(gpx_points) - 1):
        lat1, long1 = gpx_points[i].latitude, gpx_points[i].longitude
        lat2, long2 = gpx_points[i+1].latitude, gpx_points[i+1].longitude
        distance = calculate_distance(lat1, long1, lat2, long2)
        total_distance += distance
    return total_distance


# Function to calculate total time for all points in GPX file
def total_time_for_gpx(gpx_points):
    start_time = gpx_points[0].time
    end_time = gpx_points[-1].time

    if start_time is None or end_time is None:
        return timedelta(seconds=0)

    total_time = end_time - start_time
    return total_time

# Calculate average speed in km/h for all points in GPX file


def average_speed_for_gpx(gpx_points):
    total_distance = total_distance_for_gpx(gpx_points)
    total_time = total_time_for_gpx(gpx_points)

    if (total_time is None
            or total_time.total_seconds() == timedelta(seconds=0)):
        return 0

    total_time_seconds = total_time.total_seconds()

    # Convert total time to hours
    total_time_hours = total_time_seconds / 3600

    # Calculate average speed in km/h
    average_speed = (total_distance / total_time_hours
                     if total_time_hours != 0 else 0)

    return average_speed
