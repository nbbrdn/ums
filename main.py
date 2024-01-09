from flask import Flask, flash, redirect, render_template, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///ums.sqlite"
app.config["SECRET_KEY"] = "change-me"
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


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


@app.route("/user/")
def user_index():
    return render_template("user/index.html", title="User Panel")


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
