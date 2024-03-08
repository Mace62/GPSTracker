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
import math
import folium
from geopy.distance import geodesic
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
            hashed_password = bcrypt.generate_password_hash(
                form.password.data)
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
        user = models.User.query.filter_by(
            username=form.username.data).first()
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

        return redirect(url_for('display_map', filename=filename))
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(error, 'danger')
    return render_template('upload.html', form=form)


@app.route('/myfiles')
@login_required
def list_user_files():
    user_folder = os.path.join(
        app.root_path, 'static', 'uploads', str(current_user.id))
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)
    files = os.listdir(user_folder)
    file_entries = models.GPXFileData.query.filter_by(
        user_id=current_user.id).all()
    return render_template('list_files.html', files=files, file_entries=file_entries)


@app.route('/generate_map/<filename>')
@login_required
def generate_map(filename):

    user_folder = os.path.join(
        app.root_path, 'static', 'uploads', str(current_user.id))
    if not os.path.exists(os.path.join(user_folder, filename)):
        return 'File not found', 404
    gpx_file = models.GPXFileData.query.filter_by(filename=filename).first()

    waypoints = models.GPXWaypoint.query.filter_by(
        file_id=gpx_file.id).all()
    tracks = models.GPXTrack.query.filter_by(file_id=gpx_file.id).all()
    track_points = models.GPXTrackPoint.query.join(models.GPXTrack).filter(
        models.GPXTrack.file_id == gpx_file.id).all()

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

    colors = ["blue", "red", "green", "orange", "purple"]
    # create a feature group for tracks
    for i, track in enumerate(tracks):
        fg_tracks = folium.FeatureGroup(name=track.name).add_to(run_map)
        track_points = models.GPXTrackPoint.query.filter_by(
            track_id=track.id).all()

        # create a list of coordinates for the trackpoints
        track_coords = [[point.latitude, point.longitude]
                        for point in track_points]
        # create a polyline with a different color for each track
        folium.PolyLine(track_coords, color=colors[i % len(colors)],
                        weight=4.5, opacity=1).add_to(fg_tracks)

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
        'class="folium-map"', 'class="folium-map" style="width: 45%; height: 450px; border: 5px solid black;top: 10.0%; left: 5%"')

    # Save the modified HTML content back to the file
    with open(os.path.join(user_folder, map_file), 'w') as f:
        f.write(modified_html_content)

    if track_points:
        total_distance = total_distance_for_gpx(track_points)
        print(total_distance)
        total_time = total_time_for_gpx(track_points)
        print(total_time)
        average_speed = average_speed_for_gpx(track_points)
        print("Average Speed:", average_speed, "km/h")

    return run_map._repr_html_()
    # return send_from_directory(user_folder, map_file)


@app.route('/view/<filename>')
@login_required
def view(filename):
    user_folder = os.path.join(
        app.root_path, 'static', 'uploads', str(current_user.id))

    map_url = f'/generate_map/{filename}'
    return render_template('view_map.html', map_url=map_url)


@app.route('/download/<filename>')
@login_required
def download_file(filename):
    user_folder = os.path.join(
        app.root_path, 'static', 'uploads', str(current_user.id))
    if not os.path.exists(os.path.join(user_folder, filename)):
        return 'File not found', 404
    return send_from_directory(user_folder, filename, as_attachment=True)


@app.route('/delete/<filename>')
@login_required
def delete_file(filename):
    user_folder = os.path.join(
        app.root_path, 'static', 'uploads', str(current_user.id))
    if not os.path.exists(os.path.join(user_folder, filename)):
        return 'File not found', 404
    os.remove(os.path.join(user_folder, filename))
    db.session.query(models.GPXFileData).filter(
        models.GPXFileData.filename == filename).delete()
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
    total_time = end_time - start_time
    return total_time

# Calculate average speed in km/h


def average_speed_for_gpx(gpx_points):
    total_distance = total_distance_for_gpx(gpx_points)
    total_time_seconds = total_time_for_gpx(gpx_points).total_seconds()
    # Convert total time to hours
    total_time_hours = total_time_seconds / 3600
    # Calculate average speed in km/h
    average_speed = total_distance / total_time_hours
    return average_speed
