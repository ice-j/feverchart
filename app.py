from flask import Flask, render_template, request, redirect, flash, url_for, jsonify 
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy import func  
import os
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import timedelta 
from auth import admin_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bootstrap import Bootstrap
from flask_mail import Mail, Message
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer
from flask_wtf import FlaskForm
from wtforms import (
    StringField, 
    PasswordField, 
    SubmitField, 
    validators
)
from wtforms.validators import DataRequired, Email, EqualTo


load_dotenv()


# Initialize Flask app
app = Flask(__name__)

# App configuration
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'default-secret-key') 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fever.db'

bootstrap = Bootstrap(app)

# Email Configuration
app.config['MAIL_SERVER'] = 'smtp.skymail.net.br'  # Gmail's SMTP server
app.config['MAIL_PORT'] = 587  # Port for TLS
app.config['MAIL_USE_TLS'] = True  
app.config['MAIL_USE_SSL'] = False  
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USER')  
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASS') 
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('EMAIL_USER')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' 
mail = Mail(app)  # Initialize Flask-Mail

# Token serializer for email verification and password reset
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


# Database Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(100), unique=True)  # New field for email verification
    role = db.Column(db.String(50), default='user')
    password_hash = db.Column(db.String(200))  # Field to store hashed passwords
    email_verified = db.Column(db.Boolean, default=False)  # New field to track verification status
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    teams = db.relationship('Team', backref='creator', lazy=True)

    # Set password (hashing)
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # Check password (verification)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)  
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    product = db.Column(db.String(100))
    info = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    projects = db.relationship('Project', backref='team', lazy=True)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'))
    name = db.Column(db.String(100))
    total_wip = db.Column(db.Integer)
    buffer_size = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    fever_data = db.relationship('FeverChartData', backref='project', lazy=True)
    original_expected_flowtime = db.Column(db.Float)
   
class FeverChartData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'))
    current_wip = db.Column(db.Integer)
    actual_flowtime = db.Column(db.Float)  # Renamed from actual_ct
    average_flowtime = db.Column(db.Float)  # Renamed from average_ct
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    actual_throughput = db.Column(db.Float)
    expected_flowtime = db.Column(db.Float)  # Renamed from expected_ct
    flowtime_diff = db.Column(db.Float)  # Renamed from cycle_time_diff
    buffer_consumption = db.Column(db.Float)
    work_completed_pct = db.Column(db.Float)
    buffer_burn_rate = db.Column(db.Float)

# Load user for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[DataRequired(), EqualTo('password', message='Passwords must match')]
    )
    submit = SubmitField('Sign Up')


class LoginForm(FlaskForm):
    username_or_email = StringField('Username or Email', [validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])


# ====================== ROUTES ======================
@app.route('/')
@login_required
def index():
    if current_user.role == 'admin':
        teams = Team.query.all()
    else:
        teams = Team.query.filter_by(created_by=current_user.id).all()
    return render_template('index.html', teams=teams)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()  # Use the RegistrationForm class
    if form.validate_on_submit():
        # Use form data instead of request.form
        username = form.username.data
        email = form.email.data
        password = form.password.data

        # Check if user exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already registered. Please log in.", "error")
            return redirect(url_for('register'))

        # Create new user
        new_user = User(username=username, email=email, email_verified=False)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # Send verification email
        token = serializer.dumps(email, salt='email-verify')
        verification_url = url_for('verify_email', token=token, _external=True)
        msg = Message('Verify Your Email', recipients=[email])
        msg.body = f'Hi {username},\n\nVerify your email: {verification_url}'
        #mail.send(msg)

        flash(f'Registration successful! Verify here: {verification_url}', "success")
        return redirect(url_for('login'))

    return render_template('register.html', form=form)  # Pass form to template


@app.route('/verify/<token>')
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-verify', max_age=3600)  # Token expires in 1 hour (3600 seconds)
    except:
        flash("The verification link is invalid or has expired.", "error")
        return redirect(url_for('register'))

    user = User.query.filter_by(email=email).first()
    if user.email_verified:
        flash("Your email is already verified. Please log in.", "info")
    else:
        user.email_verified = True
        db.session.commit()
        flash("Your email has been verified! You can now log in.", "success")
    
    return redirect(url_for('login'))

# Password Reset Routes
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Generate password reset token
            token = serializer.dumps(user.email, salt='password-reset')
            reset_url = url_for('reset_password', token=token, _external=True)
            
            # Send password reset email
            msg = Message(
                'Password Reset Request',
                recipients=[user.email],
                body=f'''To reset your password, visit:
{reset_url}

This link expires in 1 hour.'''
            )
            mail.send(msg)
        
        flash('Check your email for password reset instructions.', 'info')
        return redirect(url_for('login'))
    
    return render_template('reset_request.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset', max_age=3600)
    except:
        flash('Invalid or expired reset link.', 'danger')
        return redirect(url_for('reset_password_request'))
    
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('register'))
    
    if request.method == 'POST':
        # Update password
        user.set_password(request.form['password'])
        db.session.commit()
        flash('Password updated successfully!', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        # Update username/email
        current_user.username = request.form['username']
        current_user.email = request.form['email']
        
        # Password change
        if request.form['new_password']:
            if current_user.check_password(request.form['current_password']):
                current_user.set_password(request.form['new_password'])
            else:
                flash('Current password is incorrect.', 'danger')
                return redirect(url_for('profile'))
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    return render_template('profile.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()  # Create an instance of the LoginForm
    if form.validate_on_submit():  # Validate the form submission
        username_or_email = form.username_or_email.data
        password = form.password.data

        # Allow login via username or email
        user = User.query.filter((User.username == username_or_email) | (User.email == username_or_email)).first()

        if user and user.check_password(password):  # Verify hashed password
            if not user.email_verified:
                flash("Please verify your email before logging in.", "error")
                return redirect(url_for('login'))

            login_user(user)
            flash("Logged in successfully!", "success")
            return redirect(url_for('index'))

        flash("Invalid credentials. Please try again.", "error")

    return render_template('login.html', form=form)  # Pass the form to the template

@app.route('/add_team', methods=['POST'])
@login_required
def add_team():
    team = Team(
        name=request.form['name'],
        product=request.form['product'],
        info=request.form['info'],  # Added missing comma here
        created_by=current_user.id
    )
    db.session.add(team)
    db.session.commit()
    flash("Team added successfully.", "success")
    return redirect('/')

@app.route('/add_project', methods=['POST'])
def add_project():
    try:
        project = Project(
            team_id=request.form['team_id'],
            name=request.form['name'],
            total_wip=int(request.form['total_wip']),
            buffer_size=int(request.form['buffer_size']),
            original_expected_flowtime=float(request.form['original_expected_flowtime'])
        )
        db.session.add(project)
        db.session.commit()
        flash("Project added successfully.", "success")
        return redirect('/')
    except ValueError:
        flash("Invalid input. Please check your values.", "error")
        return redirect('/')

@app.route('/project/<int:project_id>')
def project_detail(project_id):
    project = Project.query.get_or_404(project_id)
    fever_data = FeverChartData.query.filter_by(project_id=project_id).order_by(FeverChartData.created_at).all()
    return render_template('fever_chart.html', project=project, fever_data=fever_data)

@app.route('/api/buffer/<int:project_id>')
def get_buffer_data(project_id):
    data = FeverChartData.query.filter_by(project_id=project_id).order_by(FeverChartData.created_at).all()
    return jsonify({
        'labels': [d.created_at.strftime('%Y-%m-%d') for d in data],
        'buffer_consumption': [d.buffer_consumption for d in data],
        'burn_rate': [d.buffer_burn_rate for d in data]
    })


@app.route('/add_fever_data', methods=['POST'])
def add_fever_data():
    try:
        project_id = request.form['project_id']
        current_wip = int(request.form['current_wip'])
        actual_flowtime = float(request.form['actual_flowtime'])
        average_flowtime = float(request.form['average_flowtime'])

        if current_wip <= 0 or actual_flowtime <= 0 or average_flowtime <= 0:
            flash("All values must be greater than 0.", "error")
            return redirect(f'/project/{project_id}')

        project = Project.query.get_or_404(project_id)
        new_data = FeverChartData(
            project_id=project_id,
            current_wip=current_wip,
            actual_flowtime=actual_flowtime,
            average_flowtime=average_flowtime
        )

        # Updated calculation
        new_data.actual_throughput = (project.total_wip - current_wip) / actual_flowtime
        
        new_data.expected_flowtime = project.total_wip / new_data.actual_throughput
        new_data.flowtime_diff = new_data.expected_flowtime - average_flowtime
        new_data.buffer_consumption = (new_data.flowtime_diff / project.buffer_size) * 100
        new_data.work_completed_pct = (1 - (current_wip / project.total_wip)) * 100
        new_data.buffer_burn_rate = new_data.buffer_consumption / new_data.work_completed_pct if new_data.work_completed_pct != 0 else 0

        db.session.add(new_data)
        db.session.commit()
        flash("Fever chart data added successfully.", "success")
        return redirect(f'/project/{project_id}')
    except ValueError:
        flash("Invalid input. Please enter valid numbers.", "error")
        return redirect(f'/project/{request.form["project_id"]}')


@app.route('/update_project', methods=['POST'])
def update_project():
    try:
        project = Project.query.get(request.form['project_id'])
        new_forecasted_date = datetime.strptime(request.form['forecasted_date'], '%Y-%m-%d')
        
        project.total_wip = int(request.form['total_wip'])
        project.buffer_size = int(request.form['buffer_size'])
        project.forecasted_date = new_forecasted_date
        project.buffer_deadline = new_forecasted_date + timedelta(days=project.buffer_size)
        
        db.session.commit()
        flash("Project updated successfully.", "success")
        return redirect(f'/project/{project.id}')
    except ValueError:
        flash("Invalid input. Please check your values.", "error")
        return redirect(f'/project/{request.form["project_id"]}')
    
@app.route('/delete_project/<int:project_id>', methods=['POST'])
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)
    db.session.delete(project)
    db.session.commit()
    flash("Project deleted successfully.", "success")
    return redirect('/')

@app.route('/delete_fever_data/<int:data_id>', methods=['POST'])
def delete_fever_data(data_id):
    data_point = FeverChartData.query.get_or_404(data_id)
    project_id = data_point.project_id
    db.session.delete(data_point)
    db.session.commit()
    flash("Fever chart data point deleted successfully.", "success")
    return redirect(f'/project/{project_id}')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)
    
# ====================== MAIN ENTRY POINT ======================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
