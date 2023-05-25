import bcrypt as bcrypt
from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError

# Create Flask application instance
app = Flask(__name__)
db = SQLAlchemy()

# Configure database URI and secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'


# User model representing the User table in the database
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


# Form for user registration
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')


# Custom validation to check if the username already exists in the database
def validate_username(self, username):
    existing_user_username = User.query.filter_by(
        username=username.data).first()
    if existing_user_username:
        raise ValidationError(
            'That username already exists. Please choose a different one.')


# Home route
@app.route('/')
def home():
    url_for('login')  # Generates URL for 'login' route
    url_for('register')  # Generates URL for 'register' route
    return render_template('home.html')


# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    url_for('register')  # Generates URL for 'register' route
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.checkpw(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))  # Redirects to 'dashboard' route

        return render_template('login.html', form=form)

    return render_template('login.html', form=form)


# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    url_for('login')  # Generates URL for 'login' route
    form = RegisterForm()

    return render_template('register.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)
