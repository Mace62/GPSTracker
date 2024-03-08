from flask import *
from app import app, models, db
from flask import render_template, flash, request, redirect, url_for
from app.forms import LoginForm, RegisterForm, SearchForm
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from datetime import datetime

#app.config['SECRET_KEY'] = 'your_secret_key'

bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return models.User.query.get(int(user_id))


@app.route("/")
def show():

    if current_user.is_authenticated:
        return redirect('homepage')
    else:
        return redirect('login')


@app.route('/homepage')
@login_required
def homepage():
    return render_template('homepage.html')

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
            return redirect(url_for('homepage'))
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
            return redirect(url_for('homepage'))
        else:
            flash('Incorrect username or password. Please try again.', 'danger')

    return render_template('login.html', title="Login", form=form)

@app.route('/admin')
@login_required
def admin():
    return render_template('admin.html')




def perform_user_search(query, current_user):
    results = []
    follow_status = {}
    if query:
        results = models.User.query.filter(
            models.User.username.ilike(f'%{query}%'),
            models.User.id != current_user.id
        ).all()

        for user in results:
            # Check for requests sent by the current user
            sent_request = models.FriendRequest.query.filter_by(sender_id=current_user.id, receiver_id=user.id).first()
            if sent_request:
                follow_status[user.id] = {'status': sent_request.status, 'request_id': sent_request.id}
            else:
                # Check for requests received by the current user
                received_request = models.FriendRequest.query.filter_by(sender_id=user.id, receiver_id=current_user.id).first()
                if received_request:
                    follow_status[user.id] = {'status': received_request.status + '_received', 'request_id': received_request.id}
                else:
                    follow_status[user.id] = {'status': 'not_sent'}

    return results, follow_status

@app.route('/profile')
@login_required
def profile():
    print("current user= ",current_user)
    query = request.args.get('q')
    form = SearchForm() 
    received_requests = current_user.received_requests.filter_by(status='pending').all()
    # Fetch received friend requests

    # Fetch friends (where the current user is either the sender or receiver of an accepted friend request)
    sent_friendships = current_user.sent_requests.filter_by(status='accepted').all()
    received_friendships = current_user.received_requests.filter_by(status='accepted').all()
    # Combine and deduplicate friends
    friends = {fr.receiver for fr in sent_friendships if fr.receiver_id != current_user.id}
    friends.update({fr.sender for fr in received_friendships if fr.sender_id != current_user.id})
    print("His friend is",friends)
    print(received_requests)
    
    if query:
        results, follow_status = perform_user_search(query, current_user)
        # Update follow_status for each user based on friendship
        for user in results:
            if user in friends:
                # This user is a friend
                follow_status[user.id] = 'friend'
            else:
                # Already handled in perform_user_search: pending, accepted, not_sent, etc.
                pass

        return render_template('profile.html', form=form, query=query, results=results, user=current_user, follow_status=follow_status, received_requests=received_requests, friends=friends)
    else:
        return render_template('profile.html', form=form, query=None, results=[], user=current_user, follow_status={}, received_requests=received_requests, friends=friends)

    

@app.route('/send_friend_request/<username>', methods=['POST'])
@login_required
def send_friend_request(username):
    user_to_request = models.User.query.filter_by(username=username).first_or_404()

    # Check if the user is trying to send a friend request to themselves
    if current_user.id == user_to_request.id:
        flash("You cannot send a friend request to yourself.", "danger")
        return redirect(url_for('profile', username=username))

    # Check if there is already a friend request sent or if they are already friends
    existing_request = models.FriendRequest.query.filter(
        ((models.FriendRequest.sender_id == current_user.id) & (models.FriendRequest.receiver_id == user_to_request.id)) |
        ((models.FriendRequest.receiver_id == current_user.id) & (models.FriendRequest.sender_id == user_to_request.id))
    ).first()

    if existing_request:
        if existing_request.status == 'pending':
            flash("Friend request already sent.", "info")
        elif existing_request.status == 'accepted':
            flash("You are already friends.", "info")
        # Optionally handle 'declined' and 'removed' statuses here
    else:
        # If no existing request, create a new friend request
        new_request = models.FriendRequest(sender_id=current_user.id, receiver_id=user_to_request.id, status='pending')
        db.session.add(new_request)
        db.session.commit()
        flash(f"Friend request sent to {username}.", "success")

    return redirect(url_for('profile', username=username))


@app.route('/deny_friend_request/<int:request_id>', methods=['POST'])
@login_required
def deny_friend_request(request_id):
    request = models.FriendRequest.query.get_or_404(request_id)
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


    request = models.FriendRequest.query.get_or_404(request_id)

    # Now, using the friend request, fetch the sender and receiver
    sender = models.User.query.get(request.sender_id)
    receiver = models.User.query.get(request.receiver_id)

    # Now you can print the usernames of the sender and receiver
    print(f"Sender: {sender.username}, Receiver: {receiver.username}")
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

    # Check if the current user has a friend request with the given friend_id that's accepted
    friend_request = models.FriendRequest.query.filter(
        models.FriendRequest.status == 'accepted',
        ((models.FriendRequest.sender_id == current_user.id) & (models.FriendRequest.receiver_id == friend_id)) |
        ((models.FriendRequest.sender_id == friend_id) & (models.FriendRequest.receiver_id == current_user.id))
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
    friend_request = models.FriendRequest.query.get_or_404(request_id)
    if friend_request.sender_id == current_user.id and friend_request.status == 'pending':
        db.session.delete(friend_request)
        db.session.commit()
        flash('Friend request canceled.', 'success')
    else:
        flash('Unauthorized action or request not found.', 'danger')
    return redirect(url_for('profile'))