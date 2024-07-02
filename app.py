import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask import render_template, url_for, flash, redirect
#from models import User, Event
from flask_login import login_user, current_user, logout_user, login_required
from flask_login import LoginManager
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
#from flask import jsonify
from flask import request
from extensions import db, login_manager

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://u6vkdhl1qfuxjb3ihp8z:JUZmspQYcMTrnKUltM7OaZ0MH8lKgR@bj1jyhvnevkienngjyz0-postgresql.services.clever-cloud.com:50013/bj1jyhvnevkienngjyz0'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

login_manager.init_app(app)
login_manager.login_view = 'login'

from models import User
from models import Event

@app.route("/")
@app.route("/home")
def home():
    events = Event.query.all()
    return render_template('index.html', events=events)

@app.route("/about")
def about():
    return render_template('about.html', title='O nás')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Registrácia')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Prihlásenie')

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/event/new", methods=['GET', 'POST'])
@login_required
def new_event():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        category = request.form.get('category')
        location = request.form.get('location')
        #date_posted = request.form.get('date')
        new_event = Event(title=title, description=description, category=category, location=location, organizer=current_user)
        db.session.add(new_event)
        db.session.commit()
        flash('Your event has been created!', 'success')
        return redirect(url_for('home'))
    return render_template('create_event.html', title='Nové podujatie')

@app.route("/event/<int:event_id>")
def event(event_id):
    event = Event.query.get_or_404(event_id)
    return render_template('event_detail.html', title=event.title, event=event)

@app.route("/edit_events")
@login_required
def edit_events():
    events = Event.query.filter_by(user_id=current_user.id).all()
    return render_template('edit_events.html', title='Edit Events', events=events)

@app.route("/event/<int:event_id>/edit", methods=['GET', 'POST'])
@login_required
def edit_event(event_id):
    event = Event.query.get_or_404(event_id)
    if event.user_id != current_user.id:
        flash('You are not authorized to edit this event.', 'danger')
        return redirect(url_for('home'))
    if request.method == 'POST':
        event.title = request.form.get('title')
        event.description = request.form.get('description')
        event.category = request.form.get('category')
        event.location = request.form.get('location')
        event.date_posted = request.form.get('date_posted')
        try:
            db.session.commit()
            flash('Event updated successfully!', 'success')
            return redirect(url_for('event', event_id=event.id))
        except Exception as e:
            db.session.rollback()
            flash('Failed to update event. Please try again.', 'danger')
    return render_template('edit_event.html', title='Edit Event', event=event)

@app.route("/event/<int:event_id>/cancel", methods=['POST'])
@login_required
def cancel_event(event_id):
    event = Event.query.get_or_404(event_id)
    if event.user_id != current_user.id:
        flash('You are not authorized to cancel this event.', 'danger')
        return redirect(url_for('home'))
    try:
        db.session.delete(event)
        db.session.commit()
        flash('Event cancelled successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Failed to cancel event. Please try again.', 'danger')
    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run(debug=True)