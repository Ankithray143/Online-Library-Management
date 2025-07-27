# Library Management System Backend

This is the backend for the Library Management System, built with Flask and SQLAlchemy.

## Features

- User Authentication (Login/Register)
- Admin Dashboard
- Book Management (Add/Update/Delete)
- Book Borrowing System
- User History Tracking

## Setup Instructions

1. Install Python 3.8 or higher if not already installed

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python app.py
```

The server will start at `http://localhost:5000`

## API Endpoints

### Authentication
- POST `/api/register` - Register new user
- POST `/api/login` - Login user

### Books
- GET `/api/books` - Get all books
- POST `/api/books` - Add new book (Admin only)
- PUT `/api/books/<book_id>` - Update book (Admin only)

### Borrowing
- POST `/api/borrow/<book_id>` - Borrow a book
- POST `/api/return/<borrow_id>` - Return a book

## Database Schema

The system uses SQLite database with the following models:
- User
- Book
- BorrowedBook
