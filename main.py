from flask import Flask, flash, redirect, render_template, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///ums.sqlite"
app.config["SECRET_KEY"] = "change-me"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
Session(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(255), nullable=False)
    lname = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    status = db.Column(db.Integer, default=0, nullable=False)

    def __repr__(self):
        return f'User("{self.id}", "{self.fname}", "{self.lname}", "{self.email}", "{self.username}", "{self.status}")'


with app.app_context():
    db.create_all()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/admin/")
def admin_index():
    return render_template("admin/index.html", title="Admin Panel")


@app.route("/user/", methods=["POST", "GET"])
def user_index():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User().query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            if user.status == 0:
                flash("Your account is not approved by Admin", "danger")
                return redirect("/user/")
            else:
                session["user_id"] = user.id
                session["username"] = user.username
                flash("Login Successfully", "success")
                return redirect("/user/dashboard")
        else:
            flash("User email or password incorrect", "danger")
            return redirect("/user/")
    else:
        return render_template("user/index.html", title="User Panel")


@app.route("/user/dashboard")
def user_dashboard():
    if session.get("username"):
        return f"{session.get('username')}"


@app.route("/user/signup/", methods=["GET", "POST"])
def user_signup():
    if request.method == "POST":
        fname = request.form.get("fname")
        lname = request.form.get("lname")
        email = request.form.get("email")
        username = request.form.get("username")
        password = request.form.get("password")

        if (
            fname == ""
            or lname == ""
            or email == ""
            or password == ""
            or username == ""
        ):
            flash("Please fill all the fields", "danger")
            return redirect("/user/signup")
        else:
            stored_email = User().query.filter_by(email=email).first()
            if stored_email:
                flash("Email already exists", "danger")
                return redirect("/user/signup")
            else:
                hash_password = bcrypt.generate_password_hash(password, 10)
                user = User(
                    fname=fname,
                    lname=lname,
                    email=email,
                    username=username,
                    password=hash_password,
                )
                db.session.add(user)
                db.session.commit()
                flash(
                    "User account created successfully. Administrator will approve your account in 10 to 30 minutes.",
                    "success",
                )
                return redirect("/user/")
    else:
        return render_template("user/signup.html", title="User Signup")


if __name__ == "__main__":
    app.run(debug=True)
