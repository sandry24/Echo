from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
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
    return redirect(url_for("feed"))


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

    posts = db.execute("""
        SELECT id, user_id, content, created_at
        FROM posts
        WHERE user_id = ?
        ORDER BY created_at DESC
    """, user["id"])

    return render_template("profile.html", user=user, followed=followed, blocked=blocked,
                           followers_count=followers_count, following_count=following_count,
                           posts=posts)


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

        if len(bio) > 500:
            flash("Bio cannot exceed 500 characters!", "danger")
            return redirect(url_for("edit_profile"))

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


@app.route('/messages')
@login_required
def messages():
    """Display all current conversations"""
    user_id = session['user_id']
    conversations = db.execute('''
        SELECT c.id, u.username, 
               MAX(m.created_at) AS last_message_time, 
               lm.content AS last_message, 
               lm.sender_username AS last_message_sender
        FROM conversations c
        JOIN conversation_participants cp1 ON c.id = cp1.conversation_id
        JOIN conversation_participants cp2 ON c.id = cp2.conversation_id
        JOIN users u ON cp2.user_id = u.id
        LEFT JOIN messages m ON c.id = m.conversation_id
        LEFT JOIN (
            SELECT m2.conversation_id, 
                   m2.content, 
                   u2.username AS sender_username
            FROM messages m2
            JOIN users u2 ON u2.id = m2.sender_id
            WHERE m2.created_at = (
                SELECT MAX(m3.created_at)
                FROM messages m3
                WHERE m3.conversation_id = m2.conversation_id
            )
        ) lm ON c.id = lm.conversation_id
        WHERE cp1.user_id = ? 
          AND cp2.user_id != cp1.user_id
          AND NOT EXISTS (
              SELECT 1 FROM blocks b
              WHERE b.blocker_id = cp1.user_id AND b.blocked_id = cp2.user_id
          )
        GROUP BY c.id, u.username, lm.content, lm.sender_username
        ORDER BY last_message_time DESC
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


@app.route('/start_conversation/<int:receiver_id>', methods=['POST'])
def start_conversation(receiver_id):
    user_id = session['user_id']

    conversation = db.execute('''
        SELECT c.id 
        FROM conversations c
        JOIN conversation_participants cp1 ON c.id = cp1.conversation_id
        JOIN conversation_participants cp2 ON c.id = cp2.conversation_id
        WHERE cp1.user_id = ? AND cp2.user_id = ? OR cp1.user_id = ? AND cp2.user_id = ?
        LIMIT 1
    ''', user_id, receiver_id, receiver_id, user_id)

    if conversation:
        conversation_id = conversation[0]['id']
    else:
        db.execute('INSERT INTO conversations (created_at) VALUES (CURRENT_TIMESTAMP)')
        conversation_id = db.execute('SELECT last_insert_rowid()')[0]['last_insert_rowid()']
        db.execute('INSERT INTO conversation_participants (conversation_id, user_id) VALUES (?, ?)',
                   conversation_id, user_id)
        db.execute('INSERT INTO conversation_participants (conversation_id, user_id) VALUES (?, ?)',
                   conversation_id, receiver_id)

    return redirect(url_for('conversation', conversation_id=conversation_id))


@app.route('/send_message/<int:conversation_id>', methods=['POST'])
@login_required
def send_message(conversation_id):
    """Send a message to a user"""
    user_id = session['user_id']
    content = request.form['content']

    blocked = db.execute('''
        SELECT 1 FROM blocks
        WHERE blocker_id = (SELECT cp2.user_id FROM conversation_participants cp2
                            WHERE cp2.conversation_id = ? AND cp2.user_id != ?)
          AND blocked_id = ?
    ''', conversation_id, user_id, user_id)

    if blocked:
        flash('You cannot send a message to this user because they have blocked you.')
        return redirect(url_for('conversation', conversation_id=conversation_id))

    db.execute('INSERT INTO messages (conversation_id, sender_id, content) VALUES (?, ?, ?)',
               conversation_id, user_id, content)
    return redirect(url_for('conversation', conversation_id=conversation_id))


@app.route("/create-post", methods=["GET", "POST"])
@login_required
def create_post():
    """Allow user to create a new post"""
    if request.method == "POST":
        content = request.form.get("content")

        if not content:
            flash("Content cannot be empty!", "danger")
            return redirect(url_for("create_post"))

        if len(content) > 500:
            flash("Text cannot exceed 500 characters!", "danger")
            return redirect(url_for("create_post"))

        # Insert the new post into the database
        db.execute(
            "INSERT INTO posts (user_id, content) VALUES (?, ?)",
            session["user_id"],
            content
        )

        flash("Post created successfully!", "success")
        return redirect(url_for("feed"))  # Redirect to a feed page or another route

    return render_template("create_post.html")


@app.route("/feed")
@login_required
def feed():
    """Display the feed with posts from followed users."""
    user_id = session['user_id']

    # Fetch posts from users that the current user follows
    posts = db.execute('''
        SELECT p.id, p.user_id, p.content, p.created_at, u.username, 
               COUNT(l.id) AS like_count,
               EXISTS (
                   SELECT 1 FROM likes l2 
                   WHERE l2.user_id = ? AND l2.post_id = p.id
               ) AS liked_by_user
        FROM posts p
        JOIN users u ON p.user_id = u.id
        LEFT JOIN likes l ON p.id = l.post_id
        WHERE p.user_id = ? OR EXISTS (
            SELECT 1 FROM follows f
            WHERE f.follower_id = ? AND f.followed_id = p.user_id
        )
        GROUP BY p.id
        ORDER BY p.created_at DESC
    ''', user_id, user_id, user_id)

    comments = db.execute('''
        SELECT c.id, c.user_id, c.content, c.created_at, c.post_id, u.username 
        FROM comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.post_id IN (SELECT id FROM posts)
        ORDER BY c.created_at ASC
    ''')

    grouped_comments = {}
    for comment in comments:
        post_id = comment['post_id']
        if post_id not in grouped_comments:
            grouped_comments[post_id] = []
        grouped_comments[post_id].append(comment)

    return render_template("feed.html", posts=posts, comments=grouped_comments)


@app.route("/toggle_like/<int:post_id>", methods=["POST"])
@login_required
def toggle_like(post_id):
    """Toggle like status for a post."""
    user_id = session["user_id"]

    liked = db.execute("SELECT 1 FROM likes WHERE user_id = ? AND post_id = ?", user_id, post_id)

    if liked:
        db.execute("DELETE FROM likes WHERE user_id = ? AND post_id = ?", user_id, post_id)
    else:
        db.execute("INSERT INTO likes (user_id, post_id) VALUES (?, ?)", user_id, post_id)

    return redirect(url_for("feed"))


@app.route("/add_comment/<int:post_id>", methods=["POST"])
@login_required
def add_comment(post_id):
    """Add a comment to a post."""
    user_id = session["user_id"]
    content = request.form.get("content")

    if not content:
        flash("Comment cannot be empty!", "danger")
        return redirect(url_for("feed"))

    db.execute(
        "INSERT INTO comments (user_id, post_id, content) VALUES (?, ?, ?)",
        user_id, post_id, content
    )

    flash("Comment added successfully!", "success")
    return redirect(url_for("feed"))


@app.route("/explore")
@login_required
def explore():
    """Explore and follow new users."""
    user_id = session['user_id']

    users = db.execute('''
        SELECT u.id, u.username, u.bio 
        FROM users u
        WHERE u.id != ?
          AND NOT EXISTS (
              SELECT 1 FROM follows f
              WHERE f.follower_id = ? AND f.followed_id = u.id
          )
    ''', user_id, user_id)

    return render_template("explore.html", users=users)


@app.route("/delete_post/<int:post_id>", methods=["POST"])
@login_required
def delete_post(post_id):
    """Delete a post if it belongs to the current user."""
    user_id = session['user_id']

    # Check if the post exists and belongs to the user
    post = db.execute("SELECT * FROM posts WHERE id = ? AND user_id = ?", post_id, user_id)

    if not post:
        flash("Post not found or you do not have permission to delete it.", "danger")
        return redirect(url_for('feed'))

    # Delete the post with comments and likes first to not damage db integrity
    db.execute("DELETE FROM comments WHERE post_id = ?", post_id)
    db.execute("DELETE FROM likes WHERE post_id = ?", post_id)
    db.execute("DELETE FROM posts WHERE id = ?", post_id)

    flash("Post deleted successfully.", "success")
    redirect_page = request.args.get('redirect', 'feed')
    if redirect_page == 'profile':
        return redirect(url_for('profile', username=session['username']))
    else:
        return redirect(url_for('feed'))


@app.route("/delete_comment/<int:comment_id>", methods=["POST"])
@login_required
def delete_comment(comment_id):
    """Delete a comment if it belongs to the current user."""
    user_id = session['user_id']
    comment = db.execute("SELECT * FROM comments WHERE id = ? AND user_id = ?", comment_id, user_id)

    if not comment:
        flash("Comment not found or you do not have permission to delete it.", "danger")
        return redirect(url_for('feed'))

    db.execute("DELETE FROM comments WHERE id = ?", comment_id)

    flash("Comment deleted successfully.", "success")
    return redirect(url_for('feed'))
