from app import app, db, Team, Project

# Initialize the database within the app context
with app.app_context():
    db.create_all()  # Create tables if they don't exist
    
    # Create sample team
    team = Team(name="Alpha Team", product="Mobile App")
    db.session.add(team)
    db.session.commit()

    # Create sample project
    project = Project(
        team_id=team.id,
        name="Feature Launch",
        total_wip=100,
        buffer_size=30
    )
    db.session.add(project)
    db.session.commit()

print("Database initialized with sample data!")
