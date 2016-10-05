from flask import Flask, render_template, request, redirect, flash, session
from mysqlconnection import MySQLConnector
from flask_bcrypt import Bcrypt
import re

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
NAME_REGEX = re.compile(r'^[a-zA-Z]+[a-zA-Z-]*[a-zA-Z]+$')

app = Flask(__name__)
app.secret_key = 'supersecret'
bcrypt = Bcrypt(app)
mysql = MySQLConnector(app, 'userdashboard_alm958')

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/log')
def logpage():
    fields = None
    return render_template("login.html", fields = fields)

@app.route('/reg')
def regpage():
    fields = None
    return render_template("register.html", fields = fields)

@app.route('/main')
def main():
    username_query = "SELECT CONCAT(first_name,' ',last_name) AS name FROM users WHERE id = :userid"
    userid_data = {'userid': session['userid']['id']}
    name = mysql.query_db(username_query, userid_data)[0]['name']
    wall_query = "SELECT CONCAT(first_name,' ',last_name) AS name, messages.id as msg_id, root_msg_id, messages.created_at AS msg_date, type, content FROM messages JOIN users ON messages.user_id = users.id ORDER BY root_msg_id DESC, messages.created_at ASC"
    wall_content = mysql.query_db(wall_query)
    return render_template("wall.html", name = name, wall_content = wall_content)

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('userid', None)
    return redirect('/')

@app.route('/register', methods=['POST'])
def create():
    query = "SELECT email FROM users"
    emails = mysql.query_db(query)
    errors = False
    if len(request.form['email']) < 1:
        errors = True
        flash("e-mail address is empty. Enter e-mail.")
    elif not EMAIL_REGEX.match(request.form['email']):
        errors = True
        flash("Invalid e-mail address. Enter e-mail.")
    elif {'email' : request.form['email']} in emails:
        errors = True
        flash("The e-mail address entered already exists in the database.")
    if not NAME_REGEX.match(request.form['firstname']):
        errors = True
        flash("Firstname must be at least two characters in length containing only letters and cannot begin or end with a hyphen")
    if not NAME_REGEX.match(request.form['lastname']):
        errors = True
        flash("Lastname must be at least two characters in length containing only letters and cannot begin or end with a hyphen")
    if len(request.form['password']) < 8:
        errors = True
        flash("Password must be at least eight characters in length")
    elif request.form['password'] != request.form['password_confirmation']:
        errors = True
        flash("Password and Password Confirmation do not match.")
    if errors:
        flash("Re-enter Password and Password Confirmation.")
        return render_template('register.html', fields = request.form)
    else:
        query = "INSERT INTO users (email, first_name, middle_name, last_name, password, created_at, updated_at) VALUES(:email, :firstname, :middlename, :lastname, :password, NOW(),NOW());"
        data = {'email':request.form['email'], 'firstname' :request.form['firstname'], 'middlename' :request.form['middlename'], 'lastname' :request.form['lastname'], 'password': bcrypt.generate_password_hash(request.form['password']) }
        session['userid'] = mysql.query_db(query, data)
        print session['userid']
        return redirect('/main')

@app.route('/login', methods=['POST'])
def login():
    query = "SELECT email FROM users"
    emails = mysql.query_db(query)
    email = request.form['email']
    if not {'email' : request.form['email']} in emails:
        flash("The e-mail address " +  email +" entered was not found.  Please check the email and register if you are a new user")
        return redirect ('/')
    if request.form['password'] != request.form['password_confirmation']:
        flash("Password and Password Confirmation do not match.")
        return render_template('login.html', fields = request.form)
    password = request.form['password']
    user_query = "SELECT * FROM users WHERE email = :email LIMIT 1"
    query_data = { 'email': email }
    user = mysql.query_db(user_query, query_data) # user will be returned in a list
    if bcrypt.check_password_hash(user[0]['password'], password):
        query = "SELECT id FROM users WHERE email = :email"
        data = { 'email': email }
        session['userid'] = mysql.query_db(query, data)[0]

        return redirect('/main')
    else:
        flash("The password did not match that for " + email +". Please check the password.")
        return render_template('login.html', fields = request.form)

@app.route('/message', methods=['POST'])
def new_message():
    print 'new_message route'
    print session['userid']
    print session['userid']['id']
    message_query = "INSERT INTO messages (content, user_id, type, created_at, updated_at) VALUES(:message, :user_id, :type, NOW(), NOW());"
    message_data = {'message':request.form['content'], 'user_id' :session['userid']['id'], 'type': request.form['type']}
    newmsgid = mysql.query_db(message_query, message_data)
    print newmsgid
    query = 'UPDATE messages SET root_msg_id = :rt_msg_id WHERE id = :newmsgid'
    if request.form['type'] == 'response':
        data = {'rt_msg_id': request.form['root_msg_id'], 'newmsgid':newmsgid}
    else:
        data = {'rt_msg_id': newmsgid, 'newmsgid':newmsgid}
    mysql.query_db(query, data)
    return redirect('/main')


if __name__ == "__main__":
    app.run(debug=True)
