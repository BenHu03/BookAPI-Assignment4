# Book Library API with JWT Authentication
This is a simple Flask API that provides user registration, login with JWT, and CRUD operations for books.
SQLite is used as persistent storage, and the first run automatically seeds:

## Seed User
- username: `admin`
- password: `password`

## Seed Books
- 1984 — George Orwell
- To Kill a Mockingbird — Harper Lee
- The Great Gatsby — F. Scott Fitzgerald

## 📦 Installation
1. Install dependencies
`pip install flask flask_sqlalchemy     flask_jwt_extended werkzeug`

2. Run the app
`python book.py`

3. Database `book.db` will be created automatically with seed data.


## 🔐 Authentication
This API uses JWT for authentication.
1. Users register with `/auth/register`
2. Users login with `/auth/login`
3. Authenticated users get a JWT token (Bearer token)
4. Endpoints for POST/PUT/DELETE require JWT

## 📚 API Endpoints
### Public Endpoints (no authentication required)
| Method | Endpoint              | Description                  |
|--------|-----------------------|------------------------------|
| GET    | `/books`              | Retrieve all books           |
| GET    | `/books/<int:id>`     | Get book by ID     |

### Authentication Endpoints
| Method | Endpoint            | Body Example                                      | Response                                      |
|--------|---------------------|---------------------------------------------------|-----------------------------------------------|
| POST   | `/auth/register`    | `{"username":"bob","password":"secret123"}`      | 201 `{"msg":"registration successful"}`       |
| POST   | `/auth/login`       | `{"username":"admin","password":"password"}`     | 200 `{"access_token":"eyJ..."}`               |

**Use the token on protected routes**  
Header: `Authorization: Bearer <access_token>`

### Protected Endpoints (JWT required + ownership check for mutations)
| Method | Endpoint                  | Body Example                                      | Description                              |
|--------|---------------------------|---------------------------------------------------|------------------------------------------|
| POST   | `/books`                  | `{"title":"Dune","author":"Frank Herbert"}`       | Add new book (owner = current user)      |
| PUT    | `/books/<int:id>`         | `{"title":"New Title"}` (fields optional)         | Update book (owner only)                 |
| DELETE | `/books/<int:id>`         | —                                                 | Delete book (owner only)                 |


## 🧪 API Usage Instructions with POSTMAN

Follow these steps to test/use API

## 1. Prepare Postman Environment
- Create an environment variable:

|Key	|Value|
|-------|--------|
|`TOKEN`	|empty first|

Later, after login, fill TOKEN with access_token from login result

## 2. Test GET /books (Public)
#### Request
- Method: `GET`
- URL: `http://localhost:5000/books`
#### Expected Response
    `Status: 200 OK`
- Body contains 3 seed books.

## 3. Register New User
#### Request
- Method: `POST`
- URL: `http://localhost:5000/auth/register`
- Body → raw → JSON:
```json
{
  "username": "user1",
  "password": "pass123"
}
```
#### Expected Response
`Status: 201 Created`
```json
{ "msg": "registration successful" }
```

## 4. Login (Admin or New User)
#### Request
- Method: `POST`
- URL: `http://localhost:5000/auth/login`
- Body:
```json
{
  "username": "admin",
  "password": "password"
}
```
#### Expected Response
`Status: 200 OK`
```json
{ "access_token": "<JWT_TOKEN>" }
```
#### Save Token to Environment

Copy the token → Go to Environment → Set `TOKEN = <JWT_TOKEN>`

Now Postman can use:

`Authorization → Bearer Token → {{TOKEN}}`

## 5. Add New Book (Authenticated)
#### Request
- Method: `POST`
- URL: `http://localhost:5000/books`
- Authorization: Bearer Token → `{{TOKEN}}`
- Body:
```json
{
  "title": "New Book",
  "author": "Someone"
}
```
#### Expected Response
`Status: 201 Created`
```json
{
  "msg": "book added",
  "book_id": 4
}
```

## 6. Update Book (Authenticated + Owner Only)
Assume you’re logged in as admin and updating book ID 1.
#### Request
- Method: `PUT`
- URL: `http://localhost:5000/books/1`
- Authorization: Bearer Token
- Body:
```json
{ "title": "Updated Title" }
```
#### Expected Response
`Status: 200 OK`

`{ "msg": "book updated" }`

#### Test Unauthorized Update

Login as `user1` → try update admin's book.

Expected Response:
```json
403 Forbidden
{ "msg": "forbidden - not owner" }
```

## 7. Delete Book (Authenticated + Owner Only)
#### Request
- Method: `DELETE`
- URL: `http://localhost:5000/books/4`
- Authorization: Bearer Token

#### Expected Response
```json
200 OK
{ "msg": "book deleted" }
```
Again, try with user who is not owner → expect `403 Forbidden`.

## 8. Token Missing Test

Remove Authorization header → access protected endpoint.

Example:
```bash
POST /books
```

Expected Response:

```json
401 Missing Authorization Header
```

## 9. Invalid ID Test
```bash
GET /books/999
```

Expected:
```bash
404 book not found
```

## 10. Restart Persistency Test
- Stop the app
- Start again
- Run `GET /books`

Expected:
- Books remain saved
- New users remain saved
- `book.db` persists data

