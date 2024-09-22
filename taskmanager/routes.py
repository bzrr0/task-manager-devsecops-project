from flask import render_template, url_for, flash, redirect, request, jsonify
from flask_login import login_required, current_user, login_user, logout_user
import logging
from werkzeug.exceptions import HTTPException
from taskmanager import db, bcrypt
from taskmanager.forms import (LoginForm, RegistrationForm, UpdateUserInfoForm, 
                                UpdateUserPassword, TaskForm, UpdateTaskForm)
from taskmanager.models import User, Task

def register_routes(app):
    # Initialize logging
    logging.basicConfig(filename='app.log', level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')

    # Custom Error Handlers
    @app.errorhandler(404)
    @app.errorhandler(403)
    @app.errorhandler(500)
    def handle_http_errors(error):
        app.logger.error(f"{error.code} error: {error}")
        return render_template(f"errors/{error.code}.html"), error.code

    @app.errorhandler(HTTPException)
    def handle_http_exception(e):
        """Return JSON response for HTTP errors"""
        app.logger.error(f"Error: {e}")
        response = e.get_response()
        response.data = jsonify({
            "code": e.code,
            "name": e.name,
            "description": e.description,
        })
        response.content_type = "application/json"
        return response

    # About route
    @app.route("/about")
    def about():
        app.logger.info("Accessed About page.")
        return render_template('about.html', title='About')

    @app.route("/login", methods=['POST', 'GET'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('all_tasks'))

        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user and bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                flash('Login Successful', 'success')
                app.logger.info(f"User {user.username} logged in successfully.")
                return redirect(url_for('all_tasks'))
            else:
                flash('Login Unsuccessful. Please check Username or Password', 'danger')
                app.logger.warning(f"Failed login attempt for user {form.username.data}")

        return render_template('login.html', title='Login', form=form)

    @app.route("/logout")
    def logout():
        logout_user()
        flash('Logged out successfully', 'info')
        app.logger.info(f"User {current_user.username} logged out.")
        return redirect(url_for('login'))

    @app.route("/register", methods=['POST', 'GET'])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for('all_tasks'))

        form = RegistrationForm()
        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(username=form.username.data, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            flash(f'Account Created for {form.username.data}', 'success')
            app.logger.info(f"New user {form.username.data} registered.")
            return redirect(url_for('login'))

        return render_template('register.html', title='Register', form=form)

    @app.route("/all_tasks")
    @login_required
    def all_tasks():
        tasks = current_user.tasks
        app.logger.info(f"Displaying all tasks for user {current_user.username}")
        return render_template('all_tasks.html', title='All Tasks', tasks=tasks)

    @app.route("/add_task", methods=['POST', 'GET'])
    @login_required
    def add_task():
        form = TaskForm()
        if form.validate_on_submit():
            task = Task(content=form.task_name.data, author=current_user)
            db.session.add(task)
            db.session.commit()
            flash('Task Created', 'success')
            app.logger.info(f"User {current_user.username} created a new task: {form.task_name.data}")
            return redirect(url_for('all_tasks'))  # Corrigido aqui
        return render_template('add_task.html', form=form, title='Add Task')

    @app.route("/all_tasks/<int:task_id>/update_task", methods=['GET', 'POST'])
    @login_required
    def update_task(task_id):
        task = Task.query.get_or_404(task_id)
        form = UpdateTaskForm()
        if form.validate_on_submit():
            if form.task_name.data != task.content:
                task.content = form.task_name.data
                db.session.commit()
                flash('Task Updated', 'success')
                app.logger.info(f"User {current_user.username} updated task ID {task_id}")
                return redirect(url_for('all_tasks'))
            else:
                flash('No Changes Made', 'warning')
                return redirect(url_for('all_tasks'))
        elif request.method == 'GET':
            form.task_name.data = task.content
        return render_template('add_task.html', title='Update Task', form=form)

    @app.route("/all_tasks/<int:task_id>/delete_task")
    @login_required
    def delete_task(task_id):
        task = Task.query.get_or_404(task_id)
        db.session.delete(task)
        db.session.commit()
        flash('Task Deleted', 'info')
        app.logger.info(f"User {current_user.username} deleted task ID {task_id}")
        return redirect(url_for('all_tasks'))

    @app.route("/account", methods=['POST', 'GET'])
    @login_required
    def account():
        form = UpdateUserInfoForm()
        if form.validate_on_submit():
            if form.username.data != current_user.username:  
                current_user.username = form.username.data
                db.session.commit()
                flash('Username Updated Successfully', 'success')
                app.logger.info(f"User {current_user.username} updated their username to {form.username.data}")
                return redirect(url_for('account'))
        elif request.method == 'GET':
            form.username.data = current_user.username 

        return render_template('account.html', title='Account Settings', form=form)

    @app.route("/account/change_password", methods=['POST', 'GET'])
    @login_required
    def change_password():
        form = UpdateUserPassword()
        if form.validate_on_submit():
            if bcrypt.check_password_hash(current_user.password, form.old_password.data):
                current_user.password = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
                db.session.commit()
                flash('Password Changed Successfully', 'success')
                app.logger.info(f"User {current_user.username} changed their password.")
                return redirect(url_for('account'))
            else:
                flash('Please Enter Correct Password', 'danger')
                app.logger.warning(f"User {current_user.username} failed to change password - incorrect old password.")
        return render_template('change_password.html', title='Change Password', form=form)

    # Health Check route for monitoring
    @app.route("/health")
    def health_check():
        return jsonify({"status": "Healthy"}), 200

    # API route for real-time monitoring (hypothetical example)
    @app.route("/monitor", methods=['POST'])
    def monitor_logs():
        data = request.get_json()
        if data['anomaly']:
            app.logger.error(f"Anomaly detected in logs: {data['details']}")
        return jsonify({"status": "Monitored"}), 200
