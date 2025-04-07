from flask import Flask, render_template, request, redirect, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy import func  
import os
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import timedelta 
from auth import admin_required

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'default-secret-key') 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fever.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' 

# Database Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    role = db.Column(db.String(50), default='user')
    teams = db.relationship('Team', backref='creator', lazy=True)

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
    forecasted_date = db.Column(db.DateTime)
    buffer_deadline = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    fever_data = db.relationship('FeverChartData', backref='project', lazy=True)

class FeverChartData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'))
    current_wip = db.Column(db.Integer)
    actual_flowtime = db.Column(db.Float)  # Renamed from actual_ct
    average_ct = db.Column(db.Float)
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

# ====================== ROUTES ======================
@app.route('/')
@login_required
def index():
    if current_user.role == 'admin':
        teams = Team.query.all()
    else:
        teams = Team.query.filter_by(created_by=current_user.id).all()
    return render_template('index.html', teams=teams)

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
        forecasted_date = datetime.strptime(request.form['forecasted_date'], '%Y-%m-%d')
        buffer_size = int(request.form['buffer_size'])
        
        project = Project(
            team_id=request.form['team_id'],
            name=request.form['name'],
            total_wip=int(request.form['total_wip']),
            buffer_size=buffer_size,
            forecasted_date=forecasted_date,
            buffer_deadline=forecasted_date + timedelta(days=buffer_size)
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

@app.route('/add_fever_data', methods=['POST'])
def add_fever_data():
    try:
        project_id = request.form['project_id']
        current_wip = int(request.form['current_wip'])
        actual_flowtime = float(request.form['actual_flowtime'])  # Renamed
        average_flowtime = float(request.form['average_flowtime'])

        if current_wip <= 0 or actual_flowtime <= 0 or average_flowtime <= 0:
            flash("All values must be greater than 0.", "error")
            return redirect(f'/project/{project_id}')

        project = Project.query.get(project_id)
        new_data = FeverChartData(
            project_id=project_id,
            current_wip=current_wip,
            actual_flowtime=actual_flowtime,  # Renamed
            average_flowtime=average_flowtime
        )

        # Updated calculations
        new_data.actual_throughput = current_wip / actual_flowtime
        new_data.expected_flowtime = project.total_wip / new_data.actual_throughput  # Renamed
        new_data.flowtime_diff = new_data.expected_flowtime - average_flowtime  # Renamed
        new_data.buffer_consumption = (new_data.expected_flowtime * 100) / project.buffer_size
        new_data.work_completed_pct = (1-(current_wip / project.total_wip)) * 100
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.password == password:  # Simple password check (use hashing in production)
            login_user(user)
            flash("Logged in successfully!", "success")
            return redirect(url_for('index'))
        else:
            flash("Invalid username or password.", "error")
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "success")
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
