from flask import *
from app import app, models, db
from app.models import GPXFile
from flask import render_template, flash, request, redirect, url_for, send_from_directory
from app.forms import LoginForm, RegisterForm, UploadForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from datetime import datetime
from werkzeug.utils import secure_filename
import os
from datetime import datetime

app.config['SECRET_KEY'] = 'your_secret_key'

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

        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        filename = f"{timestamp}_{original_filename}"

        file.save(os.path.join(upload_folder, filename))  # Save the file with the new unique name

        gpx_file = GPXFile(name=filename, filepath=os.path.join(upload_folder, filename))
        gpx_file.save_to_db(current_user.id)

        flash('File successfully uploaded')

        return redirect(url_for('view_file', filename=filename))
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
    file_entries = models.GPXFileData.query.filter_by(user_id=current_user.id).all()
    return render_template('list_files.html', files=files, file_entries=file_entries)

# code to read data from the gpxwaypoint and gpxtrack tables
@app.route('/view/<filename>')
@login_required
def view_file(filename):
    user_folder = os.path.join(app.root_path, 'static', 'uploads', str(current_user.id))
    if not os.path.exists(os.path.join(user_folder, filename)):
        return 'File not found', 404
    gpx_file = models.GPXFileData.query.filter_by(filename=filename).first()
    waypoints = models.GPXWaypoint.query.filter_by(file_id=gpx_file.id).all()

    tracks = models.GPXTrack.query.filter_by(file_id=gpx_file.id).all()
    track_points = models.GPXTrackPoint.query.join(models.GPXTrack).filter(models.GPXTrack.file_id == gpx_file.id).all()
    print(gpx_file,waypoints, tracks, track_points)
    return render_template('view_file.html', waypoints=waypoints, tracks=tracks, track_points=track_points, filename=filename)


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
    db.session.query(models.GPXFileData).filter(models.GPXFileData.filename==filename).delete()
    db.session.commit()
    return redirect(url_for('list_user_files'))