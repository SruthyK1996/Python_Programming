import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from dotenv import load_dotenv
from datetime import datetime

# Print the current directory
print("Current Directory:", os.getcwd())

# Change the current directory to the script directory
script_dir = os.path.dirname(os.path.realpath(__file__))
os.chdir(script_dir)

# Print the updated directory path
print("Updated Directory:", os.getcwd())

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:12345@localhost/taskmanagementsystem'
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or secrets.token_hex(16)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    due_date = db.Column(db.DateTime)
    status = db.Column(db.String(20), nullable=False, default='in progress')
    category = db.Column(db.String(20), nullable=False, default='Normal Task')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    tasks = db.relationship('Task', backref='author', lazy=True)


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class UpdateTaskForm(FlaskForm):
    update_title = StringField('Title', validators=[DataRequired()])
    update_description = TextAreaField('Description', validators=[DataRequired()])
    update_due_date = StringField('Due Date', validators=[DataRequired()])
    update_status = SelectField('Status', choices=[('in progress', 'In Progress'), ('completed', 'Completed')], validators=[DataRequired()])
    update_category = SelectField('Category', choices=[('Normal Task', 'Normal Task'), ('Important Task', 'Important Task'), ('High Priority Task', 'High Priority Task')], validators=[DataRequired()])


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
@login_required
def index():
    # Retrieve tasks based on the selected category (if any)
    selected_category = request.args.get('category')
    if selected_category:
        tasks = Task.query.filter_by(category=selected_category, user_id=current_user.id).all()
    else:
        tasks = Task.query.filter_by(user_id=current_user.id).all()

    return render_template('index.html', tasks=tasks, form=UpdateTaskForm())


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/add_task', methods=['POST'])
@login_required
def add_task():
    title = request.form['title']
    description = request.form['description']
    due_date = datetime.strptime(request.form['due_date'], '%Y-%m-%d')
    status = request.form['status']
    category = request.form['category']
    new_task = Task(title=title, description=description, due_date=due_date, status=status, category=category, author=current_user)
    db.session.add(new_task)
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/delete_task/<int:task_id>')
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.author != current_user:
        abort(403)
    db.session.delete(task)
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/update_task/<int:task_id>', methods=['POST'])
@login_required
def update_task(task_id):
    task = Task.query.get_or_404(task_id)
    form = UpdateTaskForm()

    if form.validate_on_submit():
        task.title = form.update_title.data
        task.description = form.update_description.data
        task.due_date = datetime.strptime(form.update_due_date.data, '%Y-%m-%d')
        task.status = form.update_status.data
        task.category = form.update_category.data
        db.session.commit()
        flash('Task updated successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('index.html', tasks=Task.query.filter_by(user_id=current_user.id).all(), form=form)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
