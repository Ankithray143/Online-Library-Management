from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from datetime import datetime, timedelta
import jwt
import os
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import secrets
from dotenv import load_dotenv
from sqlalchemy import func
from werkzeug.utils import secure_filename

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Configuration
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')
app.config['UPLOAD_FOLDER'] = 'uploads'

# CORS configuration
app.config['CORS_HEADERS'] = 'Content-Type'
app.config['CORS_SUPPORTS_CREDENTIALS'] = True
app.config['CORS_ORIGINS'] = [
    "http://localhost:5000",
    "http://127.0.0.1:5000",
    "http://localhost",
    "http://127.0.0.1"
]

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    borrowed_books = db.relationship('BorrowedBook', backref='user', lazy=True)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    isbn = db.Column(db.String(13), unique=True, nullable=False)
    quantity = db.Column(db.Integer, default=1)
    available = db.Column(db.Integer, default=1)
    category = db.Column(db.String(50))
    description = db.Column(db.Text)

class BorrowedBook(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    borrow_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    return_date = db.Column(db.DateTime)
    is_returned = db.Column(db.Boolean, default=False)

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    student_id = db.Column(db.String(20), unique=True, nullable=False)
    department = db.Column(db.String(100))
    is_verified = db.Column(db.Boolean, default=False)

class Ebook(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

class Paper(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(100), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    exam_type = db.Column(db.String(50), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

class Video(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    video_url = db.Column(db.String(500), nullable=False)
    duration = db.Column(db.Integer)  # Duration in minutes
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Authentication routes
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(
        username=data['username'],
        email=data['email'],
        password_hash=hashed_password
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'Registration successful'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    
    if user and bcrypt.check_password_hash(user.password_hash, data['password']):
        token = jwt.encode(
            {'user_id': user.id, 'exp': datetime.utcnow() + timedelta(hours=24)},
            app.config['SECRET_KEY']
        )
        return jsonify({
            'token': token,
            'is_admin': user.is_admin,
            'username': user.username,
            'redirect': '/'  # Redirect to index page
        })
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/google-login', methods=['POST'])
def google_login():
    try:
        # Verify the Google token
        token = request.json.get('credential')
        idinfo = id_token.verify_oauth2_token(
            token,
            google_requests.Request(),
            app.config['GOOGLE_CLIENT_ID']
        )

        # Get user info from token
        email = idinfo['email']
        name = idinfo['name']
        
        # Check if user exists
        user = User.query.filter_by(email=email).first()
        
        if not user:
            # Create new user if doesn't exist
            username = email.split('@')[0]  # Use email prefix as username
            password = secrets.token_urlsafe(16)  # Generate random password
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            
            user = User(
                username=username,
                email=email,
                password_hash=hashed_password
            )
            db.session.add(user)
            db.session.commit()
        
        # Generate JWT token
        token = jwt.encode(
            {'user_id': user.id, 'exp': datetime.utcnow() + timedelta(hours=24)},
            app.config['SECRET_KEY']
        )
        
        return jsonify({
            'token': token,
            'username': user.username,
            'is_admin': user.is_admin,
            'redirect': '/'
        })
        
    except ValueError as e:
        # Invalid token
        return jsonify({'error': 'Invalid Google token'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# User profile route
@app.route('/api/user/profile', methods=['GET'])
@login_required
def get_user_profile():
    # Get borrowed books count
    borrowed_books_count = BorrowedBook.query.filter_by(
        user_id=current_user.id,
        is_returned=False
    ).count()
    
    # Get due books count (books due within 3 days)
    due_date_threshold = datetime.utcnow() + timedelta(days=3)
    due_books_count = BorrowedBook.query.filter(
        BorrowedBook.user_id == current_user.id,
        BorrowedBook.is_returned == False,
        BorrowedBook.return_date <= due_date_threshold
    ).count()
    
    # Calculate reading streak (simplified version)
    reading_streak = len(set([
        borrowed.borrow_date.date()
        for borrowed in current_user.borrowed_books
    ]))
    
    return jsonify({
        'username': current_user.username,
        'email': current_user.email,
        'borrowed_books_count': borrowed_books_count,
        'due_books_count': due_books_count,
        'reading_streak': reading_streak
    })

# Dashboard route
@app.route('/api/user/dashboard', methods=['GET'])
@login_required
def get_dashboard_data():
    # Get basic user stats
    borrowed_books = BorrowedBook.query.filter_by(
        user_id=current_user.id,
        is_returned=False
    ).all()
    
    # Get due soon books (due within 3 days)
    due_date_threshold = datetime.utcnow() + timedelta(days=3)
    due_soon_books = BorrowedBook.query.filter(
        BorrowedBook.user_id == current_user.id,
        BorrowedBook.is_returned == False,
        BorrowedBook.return_date <= due_date_threshold
    ).all()
    
    # Get reading streak
    reading_dates = set([
        borrowed.borrow_date.date()
        for borrowed in current_user.borrowed_books
    ])
    
    # Get recent activities
    recent_activities = []
    for borrowed in BorrowedBook.query.filter_by(user_id=current_user.id).order_by(BorrowedBook.borrow_date.desc()).limit(5):
        book = Book.query.get(borrowed.book_id)
        if borrowed.is_returned:
            recent_activities.append({
                'type': 'return',
                'description': f'Returned "{book.title}"',
                'timestamp': borrowed.return_date.isoformat()
            })
        else:
            recent_activities.append({
                'type': 'borrow',
                'description': f'Borrowed "{book.title}"',
                'timestamp': borrowed.borrow_date.isoformat()
            })
    
    # Get reading history (books borrowed per month for the last 6 months)
    today = datetime.utcnow()
    six_months_ago = today - timedelta(days=180)
    reading_history = BorrowedBook.query.filter(
        BorrowedBook.user_id == current_user.id,
        BorrowedBook.borrow_date >= six_months_ago
    ).all()
    
    # Group by month
    monthly_counts = {}
    for borrowed in reading_history:
        month = borrowed.borrow_date.strftime('%Y-%m')
        monthly_counts[month] = monthly_counts.get(month, 0) + 1
    
    # Get popular categories
    borrowed_books = BorrowedBook.query.filter_by(user_id=current_user.id).all()
    category_counts = {}
    for borrowed in borrowed_books:
        book = Book.query.get(borrowed.book_id)
        if book.category:
            category_counts[book.category] = category_counts.get(book.category, 0) + 1
    
    # Sort categories by count
    sorted_categories = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    
    return jsonify({
        'username': current_user.username,
        'borrowed_count': len(borrowed_books),
        'due_soon_count': len(due_soon_books),
        'reading_streak': len(reading_dates),
        'available_books': Book.query.filter(Book.available > 0).count(),
        'recent_activities': recent_activities,
        'reading_history': {
            'labels': list(monthly_counts.keys()),
            'data': list(monthly_counts.values())
        },
        'popular_categories': {
            'labels': [cat[0] for cat in sorted_categories],
            'data': [cat[1] for cat in sorted_categories]
        }
    })

# Book management routes
@app.route('/api/books', methods=['GET'])
def get_books():
    books = Book.query.all()
    return jsonify([{
        'id': book.id,
        'title': book.title,
        'author': book.author,
        'isbn': book.isbn,
        'available': book.available,
        'category': book.category,
        'description': book.description
    } for book in books])

@app.route('/api/books', methods=['POST'])
@login_required
def add_book():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    new_book = Book(
        title=data['title'],
        author=data['author'],
        isbn=data['isbn'],
        quantity=data['quantity'],
        available=data['quantity'],
        category=data['category'],
        description=data.get('description', '')
    )
    
    db.session.add(new_book)
    db.session.commit()
    
    return jsonify({'message': 'Book added successfully'}), 201

@app.route('/api/books/<int:book_id>', methods=['PUT'])
@login_required
def update_book(book_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    book = Book.query.get_or_404(book_id)
    data = request.get_json()
    
    book.title = data.get('title', book.title)
    book.author = data.get('author', book.author)
    book.isbn = data.get('isbn', book.isbn)
    book.quantity = data.get('quantity', book.quantity)
    book.category = data.get('category', book.category)
    book.description = data.get('description', book.description)
    
    db.session.commit()
    return jsonify({'message': 'Book updated successfully'})

# Borrowing routes
@app.route('/api/borrow/<int:book_id>', methods=['POST'])
@login_required
def borrow_book(book_id):
    book = Book.query.get_or_404(book_id)
    
    if book.available <= 0:
        return jsonify({'error': 'Book not available'}), 400
    
    borrowed = BorrowedBook(
        user_id=current_user.id,
        book_id=book_id,
        return_date=datetime.utcnow() + timedelta(days=14)
    )
    
    book.available -= 1
    db.session.add(borrowed)
    db.session.commit()
    
    return jsonify({'message': 'Book borrowed successfully'})

@app.route('/api/return/<int:borrow_id>', methods=['POST'])
@login_required
def return_book(borrow_id):
    borrowed = BorrowedBook.query.get_or_404(borrow_id)
    
    if borrowed.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    if not borrowed.is_returned:
        borrowed.is_returned = True
        borrowed.return_date = datetime.utcnow()
        book = Book.query.get(borrowed.book_id)
        book.available += 1
        db.session.commit()
        return jsonify({'message': 'Book returned successfully'})
    
    return jsonify({'error': 'Book already returned'}), 400

@app.route('/api/admin/verify-student', methods=['POST'])
@login_required
def verify_student():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    student = Student.query.filter_by(student_id=data['student_id']).first()
    
    if not student:
        return jsonify({'error': 'Student not found'}), 404
    
    student.is_verified = True
    db.session.commit()
    
    return jsonify({'message': 'Student verified successfully'}), 200

@app.route('/api/admin/books', methods=['POST'])
@login_required
def admin_add_book():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    new_book = Book(
        title=data['title'],
        author=data['author'],
        isbn=data['isbn'],
        quantity=data['quantity'],
        available=data['quantity'],
        category=data['category'],
        description=data['description']
    )
    
    db.session.add(new_book)
    db.session.commit()
    
    return jsonify({'message': 'Book added successfully', 'book': {
        'id': new_book.id,
        'title': new_book.title,
        'author': new_book.author,
        'isbn': new_book.isbn,
        'quantity': new_book.quantity,
        'available': new_book.available,
        'category': new_book.category
    }}), 201

@app.route('/api/admin/books/<int:book_id>', methods=['DELETE'])
@login_required
def admin_delete_book(book_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    book = Book.query.get_or_404(book_id)
    db.session.delete(book)
    db.session.commit()
    
    return jsonify({'message': 'Book deleted successfully'}), 200

@app.route('/api/admin/dashboard', methods=['GET'])
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    total_books = Book.query.count()
    available_books = db.session.query(func.sum(Book.available)).scalar() or 0
    borrowed_books = BorrowedBook.query.filter_by(is_returned=False).count()
    total_students = Student.query.count()
    
    return jsonify({
        'totalBooks': total_books,
        'availableBooks': available_books,
        'borrowedBooks': borrowed_books,
        'totalStudents': total_students
    })

@app.route('/api/admin/borrowed-books', methods=['GET'])
@login_required
def admin_borrowed_books():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    borrowed_books = BorrowedBook.query.filter_by(is_returned=False).all()
    books_data = []
    
    for borrowed in borrowed_books:
        book = Book.query.get(borrowed.book_id)
        user = User.query.get(borrowed.user_id)
        student = Student.query.filter_by(user_id=user.id).first()
        
        books_data.append({
            'id': borrowed.id,
            'bookTitle': book.title,
            'studentName': user.username,
            'studentId': student.student_id if student else 'N/A',
            'borrowDate': borrowed.borrow_date.strftime('%Y-%m-%d'),
            'dueDate': (borrowed.borrow_date + timedelta(days=14)).strftime('%Y-%m-%d'),
            'status': 'Overdue' if datetime.utcnow() > (borrowed.borrow_date + timedelta(days=14)) else 'Active'
        })
    
    return jsonify(books_data)

# User Management Routes
@app.route('/api/admin/users', methods=['GET'])
@login_required
def get_users():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    users = User.query.all()
    return jsonify([{
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'role': 'admin' if user.is_admin else 'student'
    } for user in users])

@app.route('/api/admin/users', methods=['POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(
        username=data['username'],
        email=data['email'],
        password_hash=hashed_password,
        is_admin=data['role'] == 'admin'
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'User added successfully'}), 201

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        return jsonify({'error': 'Cannot delete admin user'}), 400
    
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'message': 'User deleted successfully'}), 200

# E-Library Routes
@app.route('/api/admin/ebooks', methods=['GET'])
@login_required
def get_ebooks():
    ebooks = Ebook.query.all()
    return jsonify([{
        'id': ebook.id,
        'title': ebook.title,
        'subject': ebook.subject,
        'uploaded_at': ebook.uploaded_at.strftime('%Y-%m-%d')
    } for ebook in ebooks])

@app.route('/api/admin/ebooks', methods=['POST'])
@login_required
def add_ebook():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    if 'pdfFile' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['pdfFile']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not file.filename.endswith('.pdf'):
        return jsonify({'error': 'Only PDF files are allowed'}), 400
    
    # Save file
    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'ebooks', filename)
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    file.save(file_path)
    
    new_ebook = Ebook(
        title=request.form['title'],
        subject=request.form['subject'],
        file_path=file_path
    )
    
    db.session.add(new_ebook)
    db.session.commit()
    
    return jsonify({'message': 'E-book added successfully'}), 201

# Previous Year Papers Routes
@app.route('/api/admin/papers', methods=['GET'])
@login_required
def get_papers():
    papers = Paper.query.all()
    return jsonify([{
        'id': paper.id,
        'subject': paper.subject,
        'year': paper.year,
        'exam_type': paper.exam_type,
        'uploaded_at': paper.uploaded_at.strftime('%Y-%m-%d')
    } for paper in papers])

@app.route('/api/admin/papers', methods=['POST'])
@login_required
def add_paper():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    if 'pdfFile' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['pdfFile']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not file.filename.endswith('.pdf'):
        return jsonify({'error': 'Only PDF files are allowed'}), 400
    
    # Save file
    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'papers', filename)
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    file.save(file_path)
    
    new_paper = Paper(
        subject=request.form['subject'],
        year=int(request.form['year']),
        exam_type=request.form['examType'],
        file_path=file_path
    )
    
    db.session.add(new_paper)
    db.session.commit()
    
    return jsonify({'message': 'Paper added successfully'}), 201

# Video Resources Routes
@app.route('/api/admin/videos', methods=['GET'])
@login_required
def get_videos():
    videos = Video.query.all()
    return jsonify([{
        'id': video.id,
        'title': video.title,
        'subject': video.subject,
        'video_url': video.video_url,
        'duration': video.duration,
        'uploaded_at': video.uploaded_at.strftime('%Y-%m-%d')
    } for video in videos])

@app.route('/api/admin/videos', methods=['POST'])
@login_required
def add_video():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    new_video = Video(
        title=data['title'],
        subject=data['subject'],
        video_url=data['videoUrl'],
        duration=int(data['duration'])
    )
    
    db.session.add(new_video)
    db.session.commit()
    
    return jsonify({'message': 'Video added successfully'}), 201

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
