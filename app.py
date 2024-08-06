from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
import pytz

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
        session["username"] = rows[0]["username"]

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
            session["username"] = rows[0]["username"]
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


@app.route("/profile/<username>")
@login_required
def profile(username):
    """Show user profile information"""
    user = db.execute("SELECT * FROM users WHERE username=?", username)
    if not user:
        return apology("User does not exist", 404)

    user = user[0]
    followed = is_followed(session["user_id"], user["id"])
    blocked = is_blocked(session["user_id"], user["id"])
    followers_count = db.execute("SELECT COUNT(*) as cnt FROM follows WHERE followed_id=?", user["id"])[0]["cnt"]
    following_count = db.execute("SELECT COUNT(*) as cnt FROM follows WHERE follower_id=?", user["id"])[0]["cnt"]

    return render_template("profile.html", user=user, followed=followed, blocked=blocked,
                           followers_count=followers_count, following_count=following_count)


@app.route("/profile")
@login_required
def user_profile():
    """Redirect user to his own profile"""
    return redirect(url_for('profile', username=session["username"]))


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
        elif db.execute("SELECT * FROM users WHERE username=? AND id!=?", username, session["user_id"]):
            return apology("Username already exists", 400)
        else:
            # Update the user in the database
            password_hash = generate_password_hash(password) if password else user["password_hash"]
            db.execute(
                'UPDATE users SET username = ?, bio = ?, password_hash = ? WHERE id = ?',
                username, bio, password_hash, session["user_id"]
            )

            flash('Profile updated successfully!')
            session["username"] = username  # Update username in session
            return redirect(f"/profile/{username}")
    else:
        return render_template("edit_profile.html", user=user)


def is_followed(follower_id, followed_id):
    """Returns if a user follows another user"""
    return db.execute("SELECT * FROM follows WHERE follower_id = ? AND followed_id = ?", follower_id, followed_id)


def is_blocked(blocker_id, blocked_id):
    """Returns if a user blocked another user"""
    return db.execute("SELECT * FROM blocks WHERE blocker_id = ? AND blocked_id = ?", blocker_id, blocked_id)


@app.route('/follow/<int:user_id>', methods=['POST'])
@login_required
def follow_user(user_id):
    """Follow a user"""
    current_user_id = session["user_id"]
    username = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]['username']

    if current_user_id == user_id:
        flash("You cannot follow yourself.")
        return redirect(url_for('profile', username=username))

    followed = is_followed(current_user_id, user_id)

    if not followed:
        db.execute("INSERT INTO follows (follower_id, followed_id) VALUES (?, ?)", current_user_id, user_id)
        flash(f"You are now following {username}.")

    return redirect(url_for('profile', username=username))


@app.route('/unfollow/<int:user_id>', methods=['POST'])
@login_required
def unfollow_user(user_id):
    """Unfollow a user"""
    current_user_id = session["user_id"]
    username = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]['username']
    followed = is_followed(current_user_id, user_id)

    if followed:
        db.execute("DELETE FROM follows WHERE follower_id = ? AND followed_id = ?", current_user_id, user_id)
        flash(f"You have unfollowed {username}.")

    return redirect(url_for('profile', username=username))


@app.route('/block/<int:user_id>', methods=['POST'])
@login_required
def block_user(user_id):
    """Block a user"""
    current_user_id = session["user_id"]
    username = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]['username']

    if current_user_id == user_id:
        flash("You cannot block yourself.")
        return redirect(url_for('profile', username=username))

    blocked = is_blocked(current_user_id, user_id)

    if not blocked:
        db.execute("INSERT INTO blocks (blocker_id, blocked_id) VALUES (?, ?)", current_user_id, user_id)
        flash(f"You have blocked {username}.")

    return redirect(url_for('profile', username=username))


@app.route('/unblock/<int:user_id>', methods=['POST'])
@login_required
def unblock_user(user_id):
    """Unblock a user"""
    current_user_id = session["user_id"]
    username = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]['username']
    blocked = is_blocked(current_user_id, user_id)

    if blocked:
        db.execute("DELETE FROM blocks WHERE blocker_id = ? AND blocked_id = ?", current_user_id, user_id)
        flash(f"You have unblocked {username}.")

    return redirect(url_for('profile', username=username))


@app.route("/search")
@login_required
def search():
    """Search for users"""
    username = request.args.get("username")
    if username:
        users = db.execute("SELECT * FROM users WHERE username LIKE ?", "%" + username + "%")
        return render_template("search_results.html", users=users)
    else:
        return render_template("search.html")


@app.route('/message/<int:user_id>', methods=['POST'])
@login_required
def message_user(user_id):
    """Message a user"""
    current_user_id = session["user_id"]
    message_content = request.form.get("message")
    username = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]['username']

    # TODO: Implement messaging function
    flash(f"Message sent to {username}: {message_content}")

    return redirect(url_for('profile', username=username))


@app.route('/messages')
@login_required
def messages():
    """Display all current conversations"""
    user_id = session['user_id']
    conversations = db.execute('''
        SELECT c.id, u.username, MAX(m.created_at) AS last_message
        FROM conversations c
        JOIN conversation_participants cp1 ON c.id = cp1.conversation_id
        JOIN conversation_participants cp2 ON c.id = cp2.conversation_id
        JOIN users u ON cp2.user_id = u.id
        LEFT JOIN messages m ON c.id = m.conversation_id
        WHERE cp1.user_id = ? AND cp2.user_id != cp1.user_id
        GROUP BY c.id, u.username
        ORDER BY last_message DESC
    ''', user_id)
    return render_template('messages.html', conversations=conversations)


@app.route('/messages/<int:conversation_id>')
@login_required
def conversation(conversation_id):
    """Open a conversation with a user"""
    user_id = session['user_id']

    messages = db.execute('''
        SELECT m.content, m.created_at, u.username
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.conversation_id = ?
        ORDER BY m.created_at
    ''', conversation_id)

    other_user = db.execute('''
        SELECT u.username
        FROM conversation_participants cp
        JOIN users u ON cp.user_id = u.id
        WHERE cp.conversation_id = ? AND cp.user_id != ?
    ''', conversation_id, user_id)

    other_username = other_user[0]['username'] if other_user else "Unknown"
    return render_template('conversation.html', messages=messages,
                           conversation_id=conversation_id, other_username=other_username)



