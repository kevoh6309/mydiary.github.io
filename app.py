from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///diary.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ------------------ MODELS ------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class DiaryEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # Timestamp defaults to current UTC time

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ------------------ ROUTES ------------------
@app.route('/')
def home():
    return render_template('index.html')

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        user = User(username=username, password=password)
        try:
            db.session.add(user)
            db.session.commit()
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()  # In case of error, roll back the transaction
            flash(f'Error: {e}', 'danger')
    return render_template('register.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    entries = DiaryEntry.query.filter_by(user_id=current_user.id).all()

    # Ensure all entries have a valid timestamp (if any entry has None)
    for entry in entries:
        if entry.timestamp is None:
            entry.timestamp = datetime.now()  # Set to the current datetime or another default value
            db.session.commit()  # Save the changes to the database

    return render_template('dashboard.html', entries=entries)

# Write Entry
@app.route('/write', methods=['GET', 'POST'])
@login_required
def write():
    if request.method == 'POST':
        content = request.form['content']
        if content:
            entry = DiaryEntry(user_id=current_user.id, content=content)
            db.session.add(entry)
            db.session.commit()
            flash('Entry saved successfully!', 'success')
            return redirect(url_for('dashboard'))
    return render_template('write.html')

# Search Entries
@app.route('/search', methods=['GET'])
@login_required
def search():
    query = request.args.get('query', '')
    if query:
        results = DiaryEntry.query.filter(
            DiaryEntry.content.contains(query),
            DiaryEntry.user_id == current_user.id
        ).all()
    else:
        results = []
    return render_template('search_results.html', results=results, query=query)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure database tables are created before starting the app
    app.run(debug=True)
