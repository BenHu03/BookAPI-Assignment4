# book.py
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import os

app = Flask(__name__)

# --- Basic Config ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///book.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = "super-secret-key"   # change if you want
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

db = SQLAlchemy(app)
jwt = JWTManager(app)

# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(200), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --- Create DB + Seed Data ---
def seed_data():
    # if user already exists, skip seeding
    if User.query.first():
        return

    # Seed user
    admin = User(
        username="admin",
        password_hash=generate_password_hash("password")
    )
    db.session.add(admin)
    db.session.commit()

    # Seed 3 books owned by admin
    books = [
        Book(title='1984', author='George Orwell', owner_id=admin.id),
        Book(title='To Kill a Mockingbird', author='Harper Lee', owner_id=admin.id),
        Book(title='The Great Gatsby', author='F. Scott Fitzgerald', owner_id=admin.id)
    ]
    db.session.add_all(books)
    db.session.commit()

with app.app_context():
    db.create_all()
    seed_data()

# --- Auth Endpoints ---

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"msg": "username and password required"}), 400

    if User.query.filter_by(username=data["username"]).first():
        return jsonify({"msg": "username already exists"}), 400

    user = User(
        username=data["username"],
        password_hash=generate_password_hash(data["password"])
    )
    db.session.add(user)
    db.session.commit()

    return jsonify({"msg": "registration successful"}), 201


@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"msg": "username and password required"}), 400

    user = User.query.filter_by(username=data["username"]).first()
    if not user or not check_password_hash(user.password_hash, data["password"]):
        return jsonify({"msg": "invalid credentials"}), 401

    # IMPORTANT: identity must be a string to avoid "Subject must be a string" error
    token = create_access_token(identity=str(user.id))
    return jsonify({"access_token": token}), 200


# --- Books Endpoints ---

@app.route('/books', methods=['GET'])
def get_books():
    books = Book.query.all()
    result = [
        {"id": b.id, "title": b.title, "author": b.author, "owner_id": b.owner_id}
        for b in books
    ]
    return jsonify(result), 200


@app.route('/books/<int:book_id>', methods=['GET'])
def get_book(book_id):
    book = Book.query.get(book_id)
    if not book:
        return jsonify({"msg": "book not found"}), 404

    return jsonify({
        "id": book.id,
        "title": book.title,
        "author": book.author,
        "owner_id": book.owner_id
    }), 200


@app.route('/books', methods=['POST'])
@jwt_required()
def add_book():
    data = request.get_json()
    if not data or "title" not in data or "author" not in data:
        return jsonify({"msg": "title & author required"}), 400

    # convert identity back to int (we stored it as string in token)
    try:
        user_id = int(get_jwt_identity())
    except (TypeError, ValueError):
        return jsonify({"msg": "invalid token identity"}), 401

    new_book = Book(
        title=data['title'],
        author=data['author'],
        owner_id=user_id
    )
    db.session.add(new_book)
    db.session.commit()

    return jsonify({"msg": "book added", "book_id": new_book.id}), 201


@app.route('/books/<int:book_id>', methods=['PUT'])
@jwt_required()
def update_book(book_id):
    book = Book.query.get(book_id)
    if not book:
        return jsonify({"msg": "book not found"}), 404

    try:
        user_id = int(get_jwt_identity())
    except (TypeError, ValueError):
        return jsonify({"msg": "invalid token identity"}), 401

    if book.owner_id != user_id:
        return jsonify({"msg": "forbidden - not owner"}), 403

    data = request.get_json()
    if not data:
        return jsonify({"msg": "no update data"}), 400

    book.title = data.get("title", book.title)
    book.author = data.get("author", book.author)

    db.session.commit()
    return jsonify({"msg": "book updated"}), 200


@app.route('/books/<int:book_id>', methods=['DELETE'])
@jwt_required()
def delete_book(book_id):
    book = Book.query.get(book_id)
    if not book:
        return jsonify({"msg": "book not found"}), 404

    try:
        user_id = int(get_jwt_identity())
    except (TypeError, ValueError):
        return jsonify({"msg": "invalid token identity"}), 401

    if book.owner_id != user_id:
        return jsonify({"msg": "forbidden - not owner"}), 403

    db.session.delete(book)
    db.session.commit()
    return jsonify({"msg": "book deleted"}), 200


if __name__ == '__main__':
    app.run(debug=True)

