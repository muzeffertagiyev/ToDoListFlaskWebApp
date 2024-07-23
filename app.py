from flask import Flask, render_template, redirect, url_for , url_for, flash, request,session, jsonify

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from sqlalchemy import or_

from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import RegisterForm, LoginForm, TaskForm, ChangeUsernameForm, ResetPasswordForm


app = Flask(__name__)
app.config['SECRET_KEY'] = 'BYkEfBA6O6donzWlSihBXox7C0sKR6b'


@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404


@app.context_processor
def global_variables():
    users = User.query.all()
    url=''
    if current_user.is_authenticated:
        url=url_for('user_list',username=current_user.username)
    else:
      url=url_for('home')


    return dict(users=users,url=url)

# LOGIN 
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.unauthorized_handler
def unauthorized():
    session['next_url'] = request.url
    # Redirect the user to the login page if they are not authenticated
    flash('You must be logged in first','danger')
    return redirect(url_for('login'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# CREATING DATA BASE
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///todo_list.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

with app.app_context():
    class User(UserMixin,db.Model):
        __tablename__ = 'users'
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(200), nullable=False, unique=True)
        email = db.Column(db.String(300), nullable=False, unique=True)
        password = db.Column(db.String(300), nullable=False)
        tasks = relationship("Task", back_populates='user')

    class Task(db.Model):
        __tablename__ = 'tasks'
        id = db.Column(db.Integer, primary_key=True)

        user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
        user = relationship("User", back_populates="tasks")

        title = db.Column(db.String(250),nullable=False)
        description = db.Column(db.String(600), nullable=False)
        completed = db.Column(db.Boolean, default=False)
  
    db.create_all()
    
# ---------------------------------------------------------------------------

# all Flask routes below
@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for('user_list',username=current_user.username))

    return render_template('index.html')

@app.route("/home/<username>",methods=["GET","POST"])
@login_required
def user_list(username):
    user = User.query.filter_by(username=username).first_or_404()

    
    uncompleted_tasks = Task.query.filter_by(user_id=user.id, completed=False).order_by(Task.id.desc()).all()
    completed_tasks = Task.query.filter_by(user_id=user.id, completed=True).order_by(Task.id.desc()).all()

    task_form = TaskForm()
    
    if task_form.validate_on_submit():
        new_task = Task(
            user_id = current_user.id,
            title = task_form.title.data,
            description = task_form.description.data,
            completed=False
        )
        task_form.title.data = ''
        task_form.description.data = ''
        db.session.add(new_task)
        db.session.commit()
        
        flash("New Task was added successfully",'success')
        return redirect(url_for('user_list',username=current_user.username))
    return render_template('user.html',task_form=task_form, uncompleted_tasks=uncompleted_tasks, completed_tasks=completed_tasks)


@app.route('/register/', methods=["GET","POST"])
def register():
    if current_user.is_authenticated:
        flash('You are already logged in. Please logout to Register a new account.', 'danger')
        return redirect(url_for('user_list',username=current_user.username))
    
    register_form = RegisterForm()

    
    if register_form.validate_on_submit():
        entered_email = register_form.email.data
        if User.query.filter_by(email=register_form.email.data.lower()).first():
            flash('You have already signed up with that email.Log in instead','danger')
            return redirect(url_for('login'))
        
        elif User.query.filter_by(username=register_form.username.data.lower()).first():
            flash('There is user with the same name. Please enter another name','danger')
            # return redirect(url_for('register'))
            register_form.email.data = entered_email

        else:

            hashed_and_salted_password = generate_password_hash(
                password=register_form.password.data, 
                method="pbkdf2:sha256",salt_length=8)

            new_user = User(
                username=register_form.username.data.lower(),
                email=register_form.email.data.lower(),
                password=hashed_and_salted_password
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Account was created , you can login now','primary')
            return redirect(url_for('login'))


    return render_template("register.html",form=register_form)


@app.route('/login/', methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        flash('You are already logged in. Please logout to Login or to Register a new account.', 'danger')
        return redirect(url_for('user_list',username=current_user.username))
    login_form = LoginForm()

    if login_form.validate_on_submit():
        entered_email = login_form.email.data
        entered_password = login_form.password.data
        user = User.query.filter_by(email=entered_email).first()

        if not user :
            flash(f'That email does not exist,please try again Or Register','danger')
            return redirect(url_for('login'))

        elif not check_password_hash(pwhash=user.password, password=entered_password):
            flash('The password is incorrect,please try again','danger')
            login_form.email.data = entered_email
            
        else:
            login_user(user)
            next_url = session.get('next_url')
            if next_url:
                # Clear the stored next_url from the session
                session.pop('next_url', None)
                # Redirect the user back to the original URL
                return redirect(next_url)
            return redirect(url_for('user_list',username=current_user.username))
        
    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    flash('You logged out.You can login again','primary')
    return redirect(url_for('login'))


@app.route('/change_username/<username>',methods=["GET","POST"])
@login_required
def change_username(username):
    user = User.query.filter_by(username=username).first_or_404()

    update_details_form = ChangeUsernameForm(obj=user)

    if current_user.id == user.id:
        if update_details_form.validate_on_submit():

            if User.query.filter_by(username=update_details_form.username.data.lower()).first():
                flash("This username already exists",'danger')
            
            else:
                user.username = update_details_form.username.data.lower()

                db.session.commit()
                flash('Your Details Were Updated Successfully','success')
                return redirect(url_for('home',username=current_user.username))

    else:
        flash("You can only edit Your Details",'danger')
        return redirect(url_for('home',username=current_user.username))
    
    return render_template('change_username.html', form=update_details_form)


@app.route('/reset_password/<username>',methods=['GET','POST'])
@login_required
def reset_password(username):
    user = User.query.filter_by(username=username).first_or_404()
    reset_password_form = ResetPasswordForm()

    if current_user.id == user.id:

        if reset_password_form.validate_on_submit():
            old_entered_password = reset_password_form.old_password.data
            if not check_password_hash(pwhash=user.password, password=old_entered_password):
                flash('The old password is incorrect,please try again','danger')
                return redirect(url_for('reset_password',username=user.username))
            
            if old_entered_password == reset_password_form.new_password.data:
                flash("Please choose different new password from your old ones", 'danger')

            else:
                hashed_and_salted_password = generate_password_hash(
                    password=reset_password_form.new_password.data, 
                    method="pbkdf2:sha256",salt_length=8)
                
                user.password = hashed_and_salted_password

                db.session.commit()
                logout_user()
                flash('Your Password Was Reset Successfully. Please now Log In','success')
                return redirect(url_for('login'))

    else:
        flash("You can only Reset Your Password",'danger')
        return redirect(url_for('home',username=current_user.username))
    
    return render_template('reset_password.html', form=reset_password_form)


@app.route('/update/task_id/<int:id>',methods=["GET","POST"])
@login_required
def update_task(id):
    task = Task.query.get(id)
    edit_form = TaskForm(obj=task)

    if current_user.id == task.user_id:
        if edit_form.validate_on_submit():
            task.title = edit_form.title.data
            task.description = edit_form.description.data
            db.session.commit()
            flash('Task Was Updated Successfully','success')
            return redirect(url_for('user_list',username=current_user.username))
    else:
        flash("You can only edit Your Tasks",'danger')
        return redirect(url_for('user_list',username=current_user.username))


    return render_template('update_task.html',form=edit_form, task=task)


@app.route('/delete')
@login_required
def delete_task():
    task_id = request.args.get('id')
    task = Task.query.get(task_id)
    db.session.delete(task)
    db.session.commit()
    flash(f"Task '{task.title}' was deleted Successfully!",'danger')
    return redirect(url_for('user_list',username=current_user.username))


@app.route('/toggle_completion/<int:task_id>', methods=['POST'])
@login_required
def toggle_completion(task_id):
    task = Task.query.get(task_id)
    if task:
        task.completed = not task.completed
        db.session.commit()
        return jsonify({'message': 'Completion status updated successfully'})
    return jsonify({'error': 'Task not found'}), 404


if __name__ == '__main__':
    app.run(debug=True)
