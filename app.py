from flask import Flask, render_template, request, redirect, session, url_for
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

# Email Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'Email'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'password'          # Replace with your email app password

mail = Mail(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Check if email or username already exists
        existing_user = User.query.filter((User.email == email) | (User.username == username)).first()
        if existing_user:
            return "Email or Username already exists."

        # Hash password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # Send OTP
        otp = random.randint(100000, 999999)
        session['email'] = email
        session['otp'] = str(otp)
        msg = Message('Your OTP Code', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f"Your OTP is {otp}"
        mail.send(msg)
        return redirect('/verify')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['email'] = email
            return redirect(url_for('home'))

        return "Invalid credentials. Please try again."

    return render_template('login.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        otp = ''.join(request.form.getlist('otp'))
        if otp == session.get('otp'):
            return "Login Successful!"
        else:
            return "Invalid OTP. Please try again."

    return render_template('verify.html')

@app.route('/')
def home():
    if 'email' in session:
        return f"Welcome, {session['email']}!"
    return redirect('/login')

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # This ensures it runs within the application context
    app.run(debug=True)

