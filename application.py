import os
import datetime

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd


# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Query database for all symbols (company) and total shares that the user has
    rows = db.execute("SELECT symbol, SUM(shares) as shares FROM transactions WHERE userid = :userid GROUP BY symbol HAVING SUM(shares) <> 0", userid=session['user_id'])

    # User's stock assets
    total = 0

    # Update/alter the rows dictionary to store other relevant information to present on homepage
    for row in rows:
        response = lookup(row['symbol'])
        row['name'] = response['name']
        row['price'] = response['price']
        row['total'] = response['price'] * row['shares']

        # Increment asset value by calculated amount for each stock
        total += row['total']

    # Query database for the amount of cash the user has
    usercash = db.execute("SELECT cash FROM users WHERE id = :userid", userid=session['user_id'])[0]['cash']

    # Increment user's total assets by the amount of the cash that the user has
    total += usercash
    return render_template("index.html", rows=rows, cash=usercash, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached route via GET (as by clicking a link or via redirect)
    if request.method == "GET":
        return render_template("buy.html")

    # User reached route via POST (as by submitting a form via POST)
    else:

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("missing symbol")

        # Ensure shares was submitted
        elif not request.form.get("shares"):
            return apology("missing shares")

        # Look up a stock’s current price
        response = lookup(request.form.get("symbol"))

        # Ensure symbol (company) exists
        if not response:
            return apology("invalid symbol")

        else:

            # Query database to learn how much cash the user currently has
            rows = db.execute("SELECT cash FROM users WHERE id = :userid", userid=session['user_id'])

            # Ensure user can afford the number of shares at the current price
            if int(request.form.get("shares")) * response['price'] > rows[0]['cash']:
                return apology("can't afford")
            else:
                cashleft = rows[0]['cash'] - (int(request.form.get("shares")) * response['price'])
                # withdraw =  int(request.form.get("shares")) * response['price']

                # Insert transaction into database
                db.execute("INSERT INTO transactions (userid, symbol, shares, price, date) VALUES (:userid, :symbol, :shares, :price, :date)", userid=session["user_id"], symbol=response['symbol'], shares=int(request.form.get("shares")), price=response['price'], date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

                # Update user's cash value after purchase
                db.execute("UPDATE users SET cash = cashleft WHERE id = :userid", cashleft=cashleft, userid=session["user_id"])

                flash("Bought!")

                # Redirect user to home page
                return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # User reached route via GET (as by clicking a link or via redirect)
    if request.method == "GET":

        # Query database for stocks (symbols) that the user have
        rows = db.execute("SELECT symbol FROM transactions WHERE userid = :userid GROUP BY symbol HAVING SUM(shares) <> 0", userid=session["user_id"])
        return render_template("sell.html", rows=rows)

    # User reached route via POST (as by submitting a form via POST)
    else:

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("missing symbol")

        # Ensure shares were submitted
        elif not request.form.get("shares"):
            return apology("missing shares")

        # Ensure the shares are different than 0
        elif int(request.form.get("shares")) == 0:
            return apology("shares must be positive")

        else:
            # Query database for shares for the selected symbol
            rows = db.execute("SELECT SUM(shares) as shares FROM transactions WHERE userid = :userid and symbol = :symbol GROUP BY symbol HAVING SUM(shares) <> 0", userid=session["user_id"], symbol=request.form.get("symbol"))

            # Ensure the submitted shares are less than the user have
            if int(request.form.get("shares")) > rows[0]['shares']:
                return apology("too many shares")

            else:
                # Look up the selected stock's current price
                response = lookup(request.form.get("symbol"))

                # Insert the transaction into database
                db.execute("INSERT INTO transactions (userid, symbol, shares, price, date) VALUES (:userid, :symbol, :shares, :price, :date)",userid=session["user_id"], symbol=response['symbol'], shares=-int(request.form.get("shares")), price=response['price'], date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

                # Calculate the cash amount of sold stocks
                amount = int(request.form.get("shares")) * response['price']

                # Update user's cash amount
                db.execute("UPDATE users SET cash = cash + :amount WHERE id = :userid", amount=amount, userid=session["user_id"])

                flash("Sold!")

                # Redirect user to home page
                return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Query database for transactions of the user
    rows = db.execute("SELECT symbol, shares, price, date from transactions where userid = :userid", userid = session["user_id"])
    return render_template("history.html", rows=rows)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():

    # User reached route via GET (as by clicking a link or via redirect)
    if request.method == "GET":
        return render_template("settings.html")

    # User reached route via POST (as by submitting a form via POST)
    else:
        # Ensure password was submitted
        if not request.form.get("oldPassword") or not request.form.get("newPassword"):
            return apology("must provide password", 403)

        # Query database for hash of the user's password
        passwordHash = db.execute("SELECT hash FROM users WHERE id = :userid", userid=session["user_id"])[0]["hash"]

        # Ensure the user submitted the password correctly
        if not check_password_hash(passwordHash, request.form.get("oldPassword")):
            return apology("password is incorrect")

        # Ensure the new password and the confirmation password match
        elif request.form.get("newPassword") != request.form.get("confirmation"):
            return apology("passwords don't match")

        # Generate a hash value for the new password
        password_hash = generate_password_hash(request.form.get("newPassword"))

        # Update user's password hash
        db.execute("UPDATE users SET hash = :passhash WHERE id = :userid", passhash=password_hash, userid=session["user_id"])

        flash("Succesful!")
        return redirect("/")

    return apology("todo")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # User reached route via GET (as by clicking a link or via redirect)
    if request.method == "GET":
        return render_template("quote.html")

    # User reached route via POST (as by submitting a form via POST)
    else:
        symbol = request.form.get("symbol")

        # Ensure the symbol was submitted
        if not symbol:
            return apology("missing symbol")

        response = lookup(symbol)

        # Ensure symbol (company) exists
        if not response:
            return apology("invalid symbol")

        return render_template("quoted.html", name=response['name'], symbol=symbol, price=response['price'])


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via GET (as by clicking a link or via redirect)
    if request.method == "GET":
        return render_template("register.html")

    # User reached route via POST (as by submitting a form via POST)
    else:
        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("missing password")

        # Ensure password and the confirmation password match
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords don't match")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        username = request.form.get("username")
        # Generate a hash value for the submitted password
        password_hash = generate_password_hash(request.form.get("password"))

        # Register user into database
        id = db.execute("INSERT INTO users (username, hash) VALUES (:username, :password_hash)", username=username, password_hash=password_hash)

        # Remember which user has registered, hence logged in
        session["user_id"] = id

        flash("Registered!")

        # Redirect user to home page
        return redirect("/")


@app.route("/check")
def check():
    """Return true if username available, else false, in JSON format"""

    username = request.args.get("username")

    # Ensure the username was submitted and available
    if not (len(db.execute("SELECT * FROM users WHERE username = :username", username=username)) == 0) or not username:
        return jsonify(False)

    else:
        return jsonify(True)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
