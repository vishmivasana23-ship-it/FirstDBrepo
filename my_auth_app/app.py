from flask import Flask, render_template, request, redirect, url_for, session, flash
import pyodbc
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'  # Change this!

# Database connection configuration
def get_db_connection():
    # Update these settings based on your SQL Server configuration
    server = 'HEWAMANNA\SQLEXPRESS'  # or just 'localhost' or your computer name
    database = 'UserAuthDB'
    
    # For Windows Authentication (recommended for local development)
    connection_string = f'DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={server};DATABASE={database};Trusted_Connection=yes;'
    
    # If using SQL Server Authentication, use this instead:
    # username = 'your_username'
    # password = 'your_password'
    # connection_string = f'DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={server};DATABASE={database};UID={username};PWD={password}'
    
    try:
        conn = pyodbc.connect(connection_string)
        return conn
    except pyodbc.Error as e:
        print(f"Database connection error: {e}")
        return None

@app.route('/')
def home():
    if 'user_id' in session:
        return f"<h1>Welcome, {session['username']}!</h1><a href='/logout'>Logout</a>"
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Validation
        if not username or not email or not password:
            flash('All fields are required!', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long!', 'error')
            return render_template('register.html')
        
        # Hash the password
        password_hash = generate_password_hash(password)
        
        # Insert into database
        conn = get_db_connection()
        if conn is None:
            flash('Database connection failed!', 'error')
            return render_template('register.html')
        
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO NewUsers (Username, Email, PasswordHash) VALUES (?, ?, ?)",
                (username, email, password_hash)
            )
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except pyodbc.IntegrityError:
            flash('Username or email already exists!', 'error')
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'error')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not username or not password:
            flash('Please enter both username and password!', 'error')
            return render_template('login.html')
        
        conn = get_db_connection()
        if conn is None:
            flash('Database connection failed!', 'error')
            return render_template('login.html')
        
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT UserID, Username, PasswordHash FROM NewUsers WHERE Username = ?",
                (username,)
            )
            user = cursor.fetchone()
            
            if user and check_password_hash(user.PasswordHash, password):
                session['user_id'] = user.UserID
                session['username'] = user.Username
                flash('Login successful!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Invalid username or password!', 'error')
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'error')
        finally:
            conn.close()
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)