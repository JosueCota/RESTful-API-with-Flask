from dotenv import load_dotenv
import os
from flask import Flask, render_template, request, redirect, jsonify, url_for, session, abort, make_response
from flask_mysqldb import MySQL
import MySQLdb.cursors
import jwt

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET")
app.config["MYSQL_USER"] = os.getenv("DATABASE_USER")
app.config["MYSQL_PASSWORD"] = os.getenv("DATABASE_PASSWORD")
app.config["MYSQL_HOST"] = os.getenv("DATABASE_HOST")
app.config["MYSQL_DB"] = os.getenv("DATABASE_NAME")

mysql = MySQL(app)

# Error Handlers
@app.errorhandler(400)
def client_err(e):
    response = make_response(render_template('400.html', e=e))
    response.status_code = 400
    return response

@app.errorhandler(401)
def unauthorized(e):
    response = make_response(render_template('401.html', e=e))
    response.status_code = 401
    return response

@app.errorhandler(404)
def page_not_found(e):
    response = make_response(render_template('404.html', e=e))
    response.status_code = 404
    return response


@app.errorhandler(500)
def internal_err(e):
    response = make_response(render_template('500.html', e=e))
    response.status_code = 500
    return response

    
# Creates User with form input
@app.route("/register", methods=["GET","POST"])
def register():
    msg= ""
    if request.method == "POST" and "username" in request.form  and "password" in request.form:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        
        username = request.form["username"]
        password = request.form["password"]
        
        cursor.execute("SELECT * FROM users WHERE username = %s", [username])
        user = cursor.fetchone()
        
        if user: 
            # Username already exists
            msg = "User already exists!"
        elif username == "" or password == "":
            # Empty String Params
            msg = "Enter both Username and Password"
        else:
            cursor.execute("INSERT INTO users VALUES (NULL, %s, %s)", [username, password])
            mysql.connection.commit()
            return redirect(url_for("login"))
     
        # Empty Params   
    elif request.method=="POST":
        msg = "Enter both Username and Password"
        
    return render_template("register.html", msg=msg)

# Creates User with form input
@app.route("/login", methods=["GET","POST"])
def login():
    msg= ""
    if request.method == "POST" and "username" in request.form  and "password" in request.form:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        
        username = request.form["username"]
        password = request.form["password"]
        
        # Check for user
        cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", [username, password])
        user = cursor.fetchone()
        
        if not user: 
            msg = "User doesn't exist!"
        else:
            # Create jwt and store in session variable
            token = jwt.encode({
                "username": username                
            }, app.config['SECRET_KEY'])
            session["token"] = token
            return redirect(url_for("protectedRoute"))
    return render_template("login.html", msg=msg)


# Protected route
@app.route("/protected")
def protectedRoute():
    # For any routes we want to protect, we do this
    auth = protect()
    if auth[0]:
        return render_template("protectedPage.html")
    return abort(401, auth[1])
        
# Checks if user is auth
def protect():
    # Check if token has been made
    if session.get("token") is not None:
        try:
            # Decode jwt for validity
            jwt.decode(session.get("token"), app.config["SECRET_KEY"], algorithms=["HS256"])
            return (True, "Good Token")
        except jwt.ExpiredSignatureError:
            return (False, "Token Expired")
        except jwt.InvalidTokenError:
            return (False, "Invalid Token")
    return (False, "No Token")


@app.route("/")
def home():
    return render_template("home.html")

if __name__ == "__main__":
    app.run(debug=True)