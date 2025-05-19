"Demo Flask application"
import json
import os
import subprocess
import requests
import secrets
import smtplib
from email.mime.text import MIMEText
from flask import session

from flask import Flask, render_template, render_template_string, url_for, redirect, flash, g, session, request, jsonify
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import StringField, HiddenField, validators
import boto3

import config
import util

from functools import wraps
from flask import session, redirect, url_for, flash


def get_instance_document():
    try:
        r = requests.get("http://169.254.169.254/latest/dynamic/instance-identity/document")
        if r.status_code == 401:
            token=(
                requests.put(
                    "http://169.254.169.254/latest/api/token", 
                    headers={'X-aws-ec2-metadata-token-ttl-seconds': '21600'}, 
                    verify=False, timeout=1
                )
            ).text
            r = requests.get(
                "http://169.254.169.254/latest/dynamic/instance-identity/document",
                headers={'X-aws-ec2-metadata-token': token}, timeout=1
            )
        r.raise_for_status()
        return r.json()
    except:
        print(" * Instance metadata not available")
        return { "availabilityZone" : "us-fake-1a",  "instanceId" : "i-fakeabc" }

if "DYNAMO_MODE" in os.environ:
    import database_dynamo as database
else:
    import database

application = Flask(__name__)
application.secret_key = config.FLASK_SECRET

doc = get_instance_document()
availablity_zone = doc["availabilityZone"]
instance_id = doc["instanceId"]

badges = {
    "apple" : "Mac User",
    "windows" : "Windows User",
    "linux" : "Linux User",
    "video-camera" : "Digital Content Star",
    "trophy" : "Employee of the Month",
    "camera" : "Photographer",
    "plane" : "Frequent Flier",
    "paperclip" : "Paperclip Afficionado",
    "coffee" : "Coffee Snob",
    "gamepad" : "Gamer",
    "bug" : "Bugfixer",
    "umbrella" : "Seattle Fan",
}

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or (session['role'] not in roles and session['role'] != 'root'):
                flash("You do not have permission to access this page.")
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

### FlaskForm set up
class EmployeeForm(FlaskForm):
    """flask_wtf form class"""
    employee_id = HiddenField()
    photo = FileField('image')
    full_name = StringField(u'Full Name', [validators.InputRequired()])
    location = StringField(u'Location', [validators.InputRequired()])
    job_title = StringField(u'Job Title', [validators.InputRequired()])
    badges = HiddenField(u'Badges')

@application.before_request
def before_request():
    "Set up globals referenced in jinja templates"
    g.availablity_zone = availablity_zone
    g.instance_id = instance_id

@application.route("/")
def home():
    # if 'user' in session:
    #     return redirect(url_for('dashboard'))
    return render_template("main.html")

@application.route("/add")
def add():
    "Add an employee"
    form = EmployeeForm()
    return render_template("view-edit.html", form=form, badges=badges)

@application.route("/edit/<employee_id>")
@role_required('hr', 'admin')
def edit(employee_id):
    "Edit an employee"
    s3_client = boto3.client('s3')
    employee = database.load_employee(employee_id)
    signed_url = None
    if "object_key" in employee and employee["object_key"]:
        signed_url = s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket': config.PHOTOS_BUCKET, 'Key': employee["object_key"]}
        )

    form = EmployeeForm()
    form.employee_id.data = employee['id']
    form.full_name.data = employee['full_name']
    form.location.data = employee['location']
    form.job_title.data = employee['job_title']
    if 'badges' in employee:
        form.badges.data = employee['badges']

    return render_template("view-edit.html", form=form, badges=badges, signed_url=signed_url)

@application.route("/save", methods=['POST'])
def save():
    "Save an employee"
    form = EmployeeForm()
    s3_client = boto3.client('s3')
    key = None
    if form.validate_on_submit():
        if form.photo.data:
            image_bytes = util.resize_image(form.photo.data, (120, 160))
            if image_bytes:
                try:
                    # save the image to s3
                    prefix = "employee_pic/"
                    key = prefix + util.random_hex_bytes(8) + '.png'
                    s3_client.put_object(
                        Bucket=config.PHOTOS_BUCKET,
                        Key=key,
                        Body=image_bytes,
                        ContentType='image/png'
                    )
                except:
                    pass
        
        if form.employee_id.data:
            database.update_employee(
                form.employee_id.data,
                key,
                form.full_name.data,
                form.location.data,
                form.job_title.data,
                form.badges.data)
        else:
            database.add_employee(
                key,
                form.full_name.data,
                form.location.data,
                form.job_title.data,
                form.badges.data)
        flash("Saved!")
        return redirect(url_for("home"))
    else:
        return "Form failed validate"

@application.route("/employee/<employee_id>")
def view(employee_id):
    "View an employee"
    s3_client = boto3.client('s3')
    employee = database.load_employee(employee_id)
    if "object_key" in employee and employee["object_key"]:
        try:
            employee["signed_url"] = s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': config.PHOTOS_BUCKET, 'Key': employee["object_key"]}
            )
        except:
            pass
    form = EmployeeForm()

    return render_template_string("""
        {% extends "main.html" %}
        {% block head %}
            {{employee.full_name}}
            <a class="btn btn-primary float-right" href="{{ url_for("edit", employee_id=employee.id) }}">Edit</a>
            <a class="btn btn-primary float-right" href="{{ url_for('home') }}">Home</a>
        {% endblock %}
        {% block body %}

  <div class="row">
    <div class="col-md-4">
        {% if employee.signed_url %}
        <img alt="Mugshot" src="{{ employee.signed_url }}" />
        {% endif %}
    </div>

    <div class="col-md-8">
      <div class="form-group row">
        <label class="col-sm-2">{{form.location.label}}</label>
        <div class="col-sm-10">
        {{employee.location}}
        </div>
      </div>
      <div class="form-group row">
        <label class="col-sm-2">{{form.job_title.label}}</label>
        <div class="col-sm-10">
        {{employee.job_title}}
        </div>
      </div>
      {% for badge in badges %}
      <div class="form-check">
        {% if badge in employee['badges'] %}
        <span class="badge badge-primary"><i class="fa fa-{{badge}}"></i> {{badges[badge]}}</span>
        {% endif %}
      </div>
      {% endfor %}
      &nbsp;
    </div>
  </div>
</form>
        {% endblock %}
    """, form=form, employee=employee, badges=badges)

@application.route("/delete/<employee_id>")
def delete(employee_id):
    "delete employee route"
    database.delete_employee(employee_id)
    flash("Deleted!")
    return redirect(url_for("home"))

@application.route("/info")
def info():
    "Webserver info route"
    return render_template_string("""
            {% extends "main.html" %}
            {% block head %}
                Instance Info
            {% endblock %}
            {% block body %}
            <b>instance_id</b>: {{g.instance_id}} <br/>
            <b>availability_zone</b>: {{g.availablity_zone}} <br/>
            <hr/>
            <small>Stress cpu:
            <a href="{{ url_for('stress', seconds=60) }}">1 min</a>,
            <a href="{{ url_for('stress', seconds=300) }}">5 min</a>,
            <a href="{{ url_for('stress', seconds=600) }}">10 min</a>
            </small>
            {% endblock %}""")

@application.route("/info/stress_cpu/<seconds>")
def stress(seconds):
    "Max out the CPU"
    flash("Stressing CPU")
    subprocess.Popen(["stress", "--cpu", "8", "--timeout", seconds])
    return redirect(url_for("info"))

from forms import RegisterForm, LoginForm
import user_dynamo

@application.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    error = None
    if form.validate_on_submit():
        user = user_dynamo.get_user(form.username.data)
        if user:
            hashed_input, _ = user_dynamo.hash_password(form.password.data, salt=user['salt'])
            if user['password'] == hashed_input:
                session['user'] = form.username.data
                session['role'] = user.get('role', 'user')
                return redirect(url_for('dashboard'))
        error = "Invalid username or password."
    return render_template('login_email.html', form=form, error=error)

@application.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('role', None)
    return redirect(url_for('home'))

@application.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@application.route('/about')
def about():
    return "About page coming soon!"

@application.route('/contact')
def contact():
    return "Contact page coming soon!"

@application.route("/directory")
def directory():
    import boto3
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('Users')
    response = table.scan()
    employees = response.get('Items', [])
    s3_client = boto3.client('s3')
    for emp in employees:
        if emp.get('object_key'):
            try:
                emp['photo_url'] = s3_client.generate_presigned_url(
                    'get_object',
                    Params={'Bucket': "emp-photo-375e3264", 'Key': emp['object_key']},
                    ExpiresIn=3600
                )
            except Exception:
                emp['photo_url'] = None
        else:
            emp['photo_url'] = None
    return render_template('view-edit.html', employees=employees)

@application.route('/register', methods=['GET'])
def register_form():
    return render_template('register.html')

def check_hr_code(hrcode):
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('HRCode')
    response = table.get_item(Key={'code': hrcode})
    return response.get('Item')

@application.route('/register', methods=['POST'])
def register():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    hrcode = data.get('hrcode')

    hr_code_item = check_hr_code(hrcode)
    if not hr_code_item:
        return jsonify({'success': False, 'error': 'Invalid HR code.'})

    # Ensure HR code is only valid for the associated email
    if hr_code_item.get('email', '').lower() != email.lower():
        return jsonify({'success': False, 'error': 'This HR code is not valid for this email address.'})

    if user_dynamo.get_user(email):
        return jsonify({'success': False, 'error': 'Email already registered.'})

    role = hr_code_item.get('role', 'user')
    hashed_password, salt = user_dynamo.hash_password(password)
    user_dynamo.add_user(email, hashed_password, salt=salt, name=name, hrcode=hrcode, role=role)

    # Log the user in immediately after registration
    session['user'] = email
    session['role'] = role

    return jsonify({'success': True})

@application.route('/check_email', methods=['POST'])
def check_email():
    data = request.get_json()
    email = data.get('email')
    user = user_dynamo.get_user(email)
    return jsonify({'exists': bool(user)})

# Now you can use @role_required('hr') below this line

@application.route('/hr/generate_hr_code', methods=['GET', 'POST'])
@role_required('hr')
def generate_hr_code():
    if request.method == 'GET':
        return render_template('add-employee.html')
    data = request.get_json()
    email = data.get('email')
    role = data.get('role', 'user')
    if not email:
        return jsonify({'success': False, 'error': 'Email is required'})
    code = secrets.token_hex(4)
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('HRCode')
    table.put_item(Item={
        'code': code,
        'email': email,
        'role': role
    })
    return jsonify({'success': True, 'code': code})

# HR Code Management page (visible to HR and root)
@application.route('/hr/hr_codes')
@role_required('hr')
def view_hr_codes():
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('HRCode')
    response = table.scan()
    codes = response.get('Items', [])
    return render_template('hr_codes.html', codes=codes)

@application.route('/hr/revoke_hr_code', methods=['POST'])
@role_required('hr')
def revoke_hr_code():
    code = request.form['code']
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('HRCode')
    table.delete_item(Key={'code': code})
    flash('HR code revoked.')
    return redirect(url_for('view_hr_codes'))

@application.route('/hr/regenerate_hr_code', methods=['POST'])
@role_required('hr')
def regenerate_hr_code():
    email = request.form['email']
    role = request.form['role']
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('HRCode')
    # Delete all old codes for this email
    response = table.scan(FilterExpression='email = :email', ExpressionAttributeValues={':email': email})
    for item in response.get('Items', []):
        table.delete_item(Key={'code': item['code']})
    # Generate and store new code
    new_code = secrets.token_hex(4)
    table.put_item(Item={'code': new_code, 'email': email, 'role': role})
    flash(f'New HR code generated for {email}: {new_code}')
    return redirect(url_for('view_hr_codes'))

# User Management page (visible to admin and root)
@application.route('/admin/users')
@role_required('admin')
def view_users():
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('Users')
    response = table.scan()
    users = response.get('Items', [])
    return render_template('users.html', users=users)

@application.route('/admin/reset_password', methods=['POST'])
@role_required('admin')
def reset_password():
    email = request.form['email']
    new_password = request.form['new_password']
    # Get the user's current salt (or generate a new one if you want to rotate)
    user = user_dynamo.get_user(email)
    if not user:
        flash('User not found.')
        return redirect(url_for('view_users'))
    # Use the same salt for consistency
    hashed_password, _ = user_dynamo.hash_password(new_password, salt=user['salt'])
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('Users')
    table.update_item(
        Key={'username': email},
        UpdateExpression='SET password = :pwd',
        ExpressionAttributeValues={':pwd': hashed_password}
    )
    flash('Password reset.')
    return redirect(url_for('view_users'))

@application.route('/admin/deactivate_user', methods=['POST'])
@role_required('admin')
def deactivate_user():
    email = request.form['email']
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('Users')
    table.update_item(
        Key={'username': email},
        UpdateExpression='SET active = :a',
        ExpressionAttributeValues={':a': False}
    )
    flash('User deactivated.')
    return redirect(url_for('view_users'))

@application.route('/admin/activate_user', methods=['POST'])
@role_required('admin')
def activate_user():
    email = request.form['email']
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('Users')
    table.update_item(
        Key={'username': email},
        UpdateExpression='SET active = :a',
        ExpressionAttributeValues={':a': True}
    )
    flash('User activated.')
    return redirect(url_for('view_users'))

from flask import request, jsonify

@application.route('/bulk_user_action', methods=['POST'])
def bulk_user_action():
    data = request.get_json()
    action = data.get('action')
    users = data.get('users', [])
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('Users')
    for username in users:
        table.update_item(
            Key={'username': username},
            UpdateExpression='SET active = :a',
            ExpressionAttributeValues={':a': True if action == 'activate' else False}
        )
    return jsonify({'status': 'success'})

import csv
from io import StringIO
from flask import Response

@application.route('/export_directory')
def export_directory():
    import boto3
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('Users')
    response = table.scan()
    employees = response.get('Items', [])

    # Define CSV headers
    headers = ['name', 'username', 'role', 'department', 'active']

    # Create CSV in memory
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(headers)
    for emp in employees:
        row = [emp.get(h, '') for h in headers]
        cw.writerow(row)

    output = si.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=directory.csv"}
    )

@application.route('/profile/<username>')
def profile(username):
    import boto3
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('Users')
    response = table.get_item(Key={'username': username})
    emp = response.get('Item')
    if emp and emp.get('object_key'):
        s3_client = boto3.client('s3')
        try:
            emp['photo_url'] = s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': "emp-photo-375e3264", 'Key': emp['object_key']},
                ExpiresIn=3600
            )
        except Exception as e:
            emp['photo_url'] = None
    return render_template('profile.html', emp=emp)

from flask import request, redirect, url_for, session

@application.route('/edit_profile', methods=['POST'])
def edit_profile():
    username = session.get('user')
    role = session.get('role', 'user')

    # Only HR/Admin/Root can edit others' profiles
    if role in ('hr', 'admin', 'root'):
        edit_username = request.form.get('username') or username
    else:
        # Force regular users to only edit their own profile
        edit_username = username

    # If a regular user tries to edit someone else, block it
    if edit_username != username and role not in ('hr', 'admin', 'root'):
        flash('You can only edit your own profile.')
        return redirect(url_for('profile', username=username))

    name = request.form.get('name')
    department = request.form.get('department')
    photo = request.files.get('photo')
    object_key = None

    # Handle photo upload
    if photo and photo.filename:
        import boto3
        import util  # Make sure util.resize_image exists
        s3_client = boto3.client('s3')
        image_bytes = util.resize_image(photo, (120, 160))
        if image_bytes:
            object_key = f"profile_photos/{edit_username}_{secrets.token_hex(4)}.png"
            s3_client.put_object(
                Bucket="emp-photo-375e3264",
                Key=object_key,
                Body=image_bytes,
                ContentType='image/png'
            )

    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('Users')
    update_expr = 'SET #n = :n, department = :d'
    expr_attr_names = {'#n': 'name'}
    expr_attr_values = {':n': name, ':d': department}
    if object_key:
        update_expr += ', object_key = :o'
        expr_attr_values[':o'] = object_key

    table.update_item(
        Key={'username': edit_username},
        UpdateExpression=update_expr,
        ExpressionAttributeNames=expr_attr_names,
        ExpressionAttributeValues=expr_attr_values
    )
    flash('Profile updated.')
    return redirect(url_for('profile', username=edit_username))

@application.before_request
def require_login():
    # Allow these endpoints without login
    allowed_endpoints = [
        'home', 'login', 'register', 'register_form', 'check_email', 'static'
    ]
    if request.endpoint and any(request.endpoint.startswith(e) for e in allowed_endpoints):
        return  # Allow access
    if not session.get('user'):
        return redirect(url_for('home'))


