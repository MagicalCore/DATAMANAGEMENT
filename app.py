from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from functools import wraps

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Initialize database
db = SQLAlchemy(app)

# Models
class User(db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    data_entries = db.relationship('DataEntry', backref='owner', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<User {self.username}>'

class DataEntry(db.Model):
    __tablename__ = 'data_entry'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    address = db.Column(db.String(200))
    city = db.Column(db.String(50))
    country = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<DataEntry {self.full_name}>'

# Drop and recreate all tables
with app.app_context():
    db.drop_all()
    db.create_all()
    
    # Create admin user
    hashed_password = generate_password_hash('admin123')
    admin = User(username='admin', email='admin@admin.com', 
                password=hashed_password, is_admin=True)
    
    existing_admin = User.query.filter_by(username='admin').first()
    if not existing_admin:
        db.session.add(admin)
        db.session.commit()
        print("? Admin user created: username='admin', password='admin123'")
    else:
        print("? Admin user already exists")

# Make datetime available in templates
# Make datetime and models available in templates
app.jinja_env.globals.update(datetime=datetime)

# Context processor to make models available in templates
@app.context_processor
def inject_models():
    return dict(User=User, DataEntry=DataEntry)

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first!', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first!', 'warning')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('Admin access required!', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Validation
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))
        
        if len(password) < 6:
            flash('Password must be at least 6 characters!', 'danger')
            return redirect(url_for('register'))
        
        # Check if username or email exists
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing_user:
            if existing_user.username == username:
                flash('Username already exists!', 'danger')
            else:
                flash('Email already registered!', 'danger')
            return redirect(url_for('register'))
        
        # Create new user
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            flash('Login successful!', 'success')
            
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password!', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('home'))

# User Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    data_entries = DataEntry.query.filter_by(user_id=user.id).order_by(DataEntry.created_at.desc()).all()
    
    return render_template('dashboard.html', 
                         user=user,
                         entries=data_entries,
                         total_entries=len(data_entries))

# Add Data Entry
@app.route('/add_entry', methods=['POST'])
@login_required
def add_entry():
    user_id = session['user_id']
    
    # Check if email already exists for this user
    email = request.form.get('email')
    if email:
        existing_entry = DataEntry.query.filter_by(user_id=user_id, email=email).first()
        if existing_entry:
            flash('Email already exists in your data!', 'warning')
            return redirect(url_for('dashboard'))
    
    # Create new entry
    new_entry = DataEntry(
        user_id=user_id,
        full_name=request.form['full_name'],
        email=email,
        phone=request.form.get('phone'),
        address=request.form.get('address'),
        city=request.form.get('city'),
        country=request.form.get('country')
    )
    
    db.session.add(new_entry)
    db.session.commit()
    
    flash('Data added successfully!', 'success')
    return redirect(url_for('dashboard'))

# Edit Data Entry
@app.route('/edit_entry/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_entry(id):
    entry = DataEntry.query.filter_by(id=id, user_id=session['user_id']).first()
    
    if not entry:
        flash('Entry not found!', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Check if email already exists (excluding current entry)
        new_email = request.form.get('email')
        if new_email and new_email != entry.email:
            existing = DataEntry.query.filter_by(
                user_id=session['user_id'], 
                email=new_email
            ).filter(DataEntry.id != id).first()
            if existing:
                flash('Email already exists in your data!', 'warning')
                return redirect(url_for('edit_entry', id=id))
        
        entry.full_name = request.form['full_name']
        entry.email = new_email
        entry.phone = request.form.get('phone')
        entry.address = request.form.get('address')
        entry.city = request.form.get('city')
        entry.country = request.form.get('country')
        
        db.session.commit()
        flash('Data updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('edit_entry.html', entry=entry)

# Delete Data Entry
@app.route('/delete_entry/<int:id>')
@login_required
def delete_entry(id):
    entry = DataEntry.query.filter_by(id=id, user_id=session['user_id']).first()
    
    if entry:
        db.session.delete(entry)
        db.session.commit()
        flash('Data deleted successfully!', 'success')
    
    return redirect(url_for('dashboard'))

# View All Data
@app.route('/view_data')
@login_required
def view_data():
    user_id = session['user_id']
    entries = DataEntry.query.filter_by(user_id=user_id).order_by(DataEntry.created_at.desc()).all()
    return render_template('view_data.html', entries=entries)

# Admin Dashboard
@app.route('/admin')
@admin_required
def admin_dashboard():
    total_users = User.query.count()
    total_entries = DataEntry.query.count()
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    recent_entries = DataEntry.query.order_by(DataEntry.created_at.desc()).limit(5).all()
    
    return render_template('admin_dashboard.html',
                         total_users=total_users,
                         total_entries=total_entries,
                         recent_users=recent_users,
                         recent_entries=recent_entries)

# Admin - View All Users
@app.route('/admin/users')
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin_users.html', users=users)

# Admin - Delete User
@app.route('/admin/delete_user/<int:id>')
@admin_required
def admin_delete_user(id):
    user = User.query.get(id)
    
    if user and user.id != session['user_id']:
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.username} deleted successfully!', 'success')
    elif user and user.id == session['user_id']:
        flash('Cannot delete yourself!', 'danger')
    
    return redirect(url_for('admin_users'))

# Admin - View All Entries
@app.route('/admin/entries')
@admin_required
def admin_entries():
    entries = DataEntry.query.order_by(DataEntry.created_at.desc()).all()
    return render_template('admin_entries.html', entries=entries)

# Admin - Delete Any Entry
@app.route('/admin/delete_entry/<int:id>')
@admin_required
def admin_delete_entry(id):
    entry = DataEntry.query.get(id)
    
    if entry:
        db.session.delete(entry)
        db.session.commit()
        flash('Entry deleted successfully!', 'success')
    
    return redirect(url_for('admin_entries'))

# Profile Page
@app.route('/profile')
@login_required
def profile():
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

# Update Profile
@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    user = User.query.get(session['user_id'])
    username = request.form['username']
    email = request.form['email']
    
    # Check if username or email already exists (excluding current user)
    existing_user = User.query.filter(
        (User.username == username) | (User.email == email)
    ).filter(User.id != user.id).first()
    
    if existing_user:
        if existing_user.username == username:
            flash('Username already exists!', 'danger')
        else:
            flash('Email already registered!', 'danger')
        return redirect(url_for('profile'))
    
    user.username = username
    user.email = email
    
    # Update password if provided
    new_password = request.form.get('new_password')
    if new_password:
        if len(new_password) < 6:
            flash('Password must be at least 6 characters!', 'danger')
            return redirect(url_for('profile'))
        user.password = generate_password_hash(new_password)
    
    db.session.commit()
    session['username'] = username
    flash('Profile updated successfully!', 'success')
    return redirect(url_for('profile'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

