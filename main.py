from flask import Flask, flash, request, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from website.views import views, initialize_admin
from website.models import db
from flask_login import LoginManager
from website.models import User
from website.views import admin_instance
from flask import send_from_directory

"""
sample user : user1@gmail.com
    password: zxcvbnm

adminuser   : admin@example.com
    password: admin
"""

app=Flask(__name__)
app.config["SECRET_KEY"]='jkndsfakndfklasmlk'
app.config['SQLALCHEMY_DATABASE_URI']="sqlite:///ums.sqlite"
app.config['UPLOAD_FOLDER'] = 'upload_folder'

# Route to serve uploaded files
@app.route('/upload_folder/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

db.init_app(app)
admin_instance.init_app(app)
bcrypt=Bcrypt(app)
login_manager = LoginManager()
login_manager.login_view = 'views.adminDashboard'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

@app.route('/<filename>')
def serve_audio(filename):
    try:
        flash('Audio received')
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except FileNotFoundError:
        flash('Audio file not found!', 'error')
        return redirect(request.referrer or '/')
    
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        initialize_admin()  
        app.register_blueprint(views, url_prefix='/')
        app.run(debug=True)
    