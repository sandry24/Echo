from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required


app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///echo.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    session.clear()

    if request.method == "POST":
        if not request.form.get("username"):
            return apology("Must provide username", 400)

        elif not request.form.get("password"):
            return apology("Must provide password", 400)

        rows = db.execute(
            "SELECT * FROM users WHERE username = ?",
            request.form.get("username")
        )

        if len(rows) != 1 or not check_password_hash(
            rows[0]["password_hash"], request.form.get("password")
        ):
            return apology("Invalid username and/or password", 400)

        session["user_id"] = rows[0]["id"]

        return redirect("/")
    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("Must provide username", 400)

        elif not request.form.get("password"):
            return apology("Must provide password", 400)

        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("Passwords do not match", 400)

        # Ensure this username does not exist
        try:
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                request.form.get("username"),
                generate_password_hash(request.form.get("password"))
            )

            rows = db.execute(
                "SELECT * FROM users WHERE username = ?", request.form.get("username")
            )

            session["user_id"] = rows[0]["id"]
            flash(f"Successfully registered!")
        except ValueError:
            return apology("Username already exists", 400)

        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/logout")
def logout():
    """Log user out"""
    session.clear()
    return redirect("/")


@app.route("/profile", methods=["GET"])
@login_required
def profile():
    """Show user profile information"""
    user = db.execute("SELECT * FROM users WHERE id=?", session["user_id"])[0]
    return render_template("profile.html", user=user)


@app.route("/edit-profile", methods=["GET", "POST"])
@login_required
def edit_profile():
    """Let user edit profile information"""
    user = db.execute("SELECT * FROM users WHERE id=?", session["user_id"])[0]

    if request.method == "POST":
        username = request.form['username']
        bio = request.form['bio']
        password = request.form['password']
        if not username:
            return apology("Must provide username", 400)
        elif db.execute("SELECT * FROM users WHERE username=?", username):
            return apology("Username already exists", 400)
        else:
            # Update the user in the database
            password_hash = generate_password_hash(password) if password else user["password_hash"]
            db.execute(
                'UPDATE users SET username = ?, bio = ?, password_hash = ? WHERE id = ?',
                username, bio, password_hash, session["user_id"]
            )
            flash('Profile updated successfully!')
            return redirect("/profile")
    else:
        return render_template("edit_profile.html", user=user)


@app.route("/search", methods=["GET"])
@login_required
def search():
    username = request.args.get("username")
    if username:
        users = db.execute("SELECT * FROM users WHERE username LIKE ?", "%" + username + "%")
        return render_template("search_results.html", users=users)
    else:
        return render_template("search.html")
