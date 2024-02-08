from .models import *
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_user, login_required, logout_user, current_user
from flask_admin import Admin as FlaskAdmin, AdminIndexView
from flask_admin.menu import MenuLink
from flask_admin.contrib.sqla import ModelView
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt()

#for audio file
import os
from flask import current_app as app
from werkzeug.utils import secure_filename
#end

views = Blueprint('views', __name__)
class UserAdminView(ModelView):
    column_list = ('id', 'email', 'password', 'first_name', 'is_creator', 'playlists', 'songs')
    def songs(self, view, context, model, name):
        return ', '.join([song.title for song in model.songs])
    def playlists(self, view, context, model, name):
        return ', '.join([playlist.name for playlist in model.playlists])
    def on_model_change(self, form, model, is_created):
        password = form.password.data
        if password: 
            if is_created:
                model.password = bcrypt.generate_password_hash(password).decode('utf-8')
            else:
                if model.password != password:
                    model.update_password(password)
        if model.email != form.email.data:
            model.email = form.email.data
        if model.first_name != form.first_name.data:
            model.first_name = form.first_name.data
        super().on_model_change(form, model, is_created)
    can_create = True
    can_edit = True

class SongAdminView(ModelView):
    column_list = ('id', 'title', 'artist', 'user', 'playlists')
    def user(self, view, context, model, name):
        return model.user.email if model.user else None
    def playlists(self, view, context, model, name):
        return ', '.join([playlist.name for playlist in model.playlists])
    can_create = True
    can_edit = True

class PlaylistAdminView(ModelView):
    column_list = ('id', 'name', 'user', 'songs')
    def user(self, view, context, model, name):
        return model.user.email if model.user else None
    def songs(self, view, context, model, name):
        return ', '.join([song.title for song in model.songs])
    can_create = True
    can_edit = True

class CustomAdminIndexView(AdminIndexView):
    def is_visible(self):
        return False
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin
    def inaccessible_callback(self, name, **kwargs):
        flash('You are not an admin.', 'error')
        return redirect(url_for('views.index'))

admin_instance = FlaskAdmin(index_view=CustomAdminIndexView())
admin_instance.add_view(UserAdminView(User, db.session))
admin_instance.add_view(SongAdminView(Song, db.session))
admin_instance.add_view(PlaylistAdminView(Playlist, db.session))
admin_instance.add_link(MenuLink(name='Admin Dashboard', category='', url='/admin/dashboard'))

# main index 
@views.route('/')
def index():
    user = current_user
    return render_template('index.html',title="", user=user)


# -------------------------user area-----------------------------------------------------------------------------------------
@views.route('/user/login', methods=['GET', 'POST'])
def userLogin():
    from main import bcrypt
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            flash('Logged in successfully!', category='success')
            login_user(user, remember=True)
            return redirect(url_for('views.userDashboard'))
        else:
            flash('Invalid Email and Password', 'danger')
            return redirect('/user/login')
    else:
        return render_template('user/login.html', title="User Login")


@views.route('/user/sign_up', methods=['GET', 'POST'])
def userSignup():
    from main import bcrypt

    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            hash_password=bcrypt.generate_password_hash(password1,10)
            new_user = User(email=email, first_name=first_name, password=hash_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created!', category='success')
            return redirect(url_for('views.userLogin'))
    return render_template("user/sign_up.html", user=current_user)


@views.route('/logout')
@login_required
def userLogout():
    logout_user()
    return redirect(url_for('views.index'))
    

@views.route('/user/dashboard', methods=['GET', 'POST'])
@login_required
def userDashboard():
    user = current_user
    songs = Song.query.all()
    users_songs = Song.query.filter_by(user_id=user.id).all()
    playlists = Playlist.query.filter_by(user_id=user.id).all()

    if request.method == 'POST':
        # Check if the delete button for a playlist was clicked
        playlist_id_to_delete = request.form.get('deletePlaylist')
        if playlist_id_to_delete:
            playlist_to_delete = Playlist.query.get(playlist_id_to_delete)
            if playlist_to_delete:
                playlist_to_delete.delete()
                flash('Playlist deleted successfully!', 'success')
                return redirect(url_for('views.userDashboard'))
    return render_template('user/dashboard.html', title="User Dashboard", user=user, users_songs=users_songs, songs=songs, playlists=playlists)


# -------------------------Admin area--------------------------------------------------------------------------------------------------------
@views.route('/admin/login', methods=['GET', 'POST'])
def adminLogin():
    from main import bcrypt
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        admin_user = User.query.filter_by(email=email, is_admin=True).first()
        if admin_user and bcrypt.check_password_hash(admin_user.password, password):
            flash('Logged in successfully as admin!', category='success')
            login_user(admin_user, remember=True)
            return redirect(url_for('views.adminDashboard'))
        else:
            flash('Invalid Email and Password for admin', 'danger')
            return redirect('/admin/login')
    else:
        return render_template('/admin/login.html', title="Admin Login")

def initialize_admin():
    from main import bcrypt
    # Check if the admin user already exists
    admin_exists = User.query.filter_by(email='admin@example.com', is_admin=True).first()
    if not admin_exists:
        # Create a new admin user
        default_password = 'admin'
        hashed_password = bcrypt.generate_password_hash(default_password).decode('utf-8')
        admin_user = User(email='admin@example.com', password=hashed_password, is_admin=True)
        db.session.add(admin_user)
        db.session.commit()
        print('Admin user created successfully.')
    else:
        print('Admin user already exists.')


@views.route('/admin/logout')
@login_required
def adminLogout():
    logout_user()
    return redirect(url_for('views.index'))

@views.route('/admin/dashboard', methods=['GET', 'POST'])
@login_required
def adminDashboard():
    initialize_admin()
    if current_user.is_authenticated and current_user.is_admin:
        users = User.query.all()
        songs = Song.query.all()    
        num_users = User.query.count()
        num_songs = Song.query.count()
        num_creators = User.query.filter_by(is_creator=True).count()
        return render_template('admin/dashboard.html', title="Admin Dashboard", users=users, songs=songs, num_users=num_users, num_songs=num_songs, num_creators=num_creators)
    flash('You are not an admin.', 'error')
    return redirect(url_for('views.index'))


# -------------------------Song area--------------------------------------------------------------------------------------------------------
@views.route('/song/<int:song_id>')
def song_details(song_id):
    song = Song.query.get(song_id)
    if song:
        song.audio_file_path = song.audio_file_path.replace("\\", "/")
        return render_template('song_details.html', title=f"Song Details - {song.title}", song=song, audio_file_path=song.audio_file_path)
    else:
        flash('Song not found', 'error')
        return redirect(url_for('views.userDashboard'))
    
@views.route('/search_song', methods=['GET'])
def search_song():
    title = request.args.get('title')
    if title:
        song = Song.query.filter(Song.title.ilike(f'%{title}%')).first()
        if song:
            return redirect(url_for('views.song_details', song_id=song.id))
        else:
            flash('Song not found for the given title.', 'error')
            return redirect(url_for('views.userDashboard'))
    else:
        flash('Please enter a song title.', 'error')
        return redirect(url_for('views.userDashboard'))


@views.route('/create_playlist', methods=['GET', 'POST'])
@login_required
def create_playlist():
    user = current_user
    if request.method == 'POST':
        playlist_name = request.form.get('playlistName')
        selected_songs = request.form.getlist('selectedSongs')

        if not playlist_name:
            flash('Playlist name is required.', 'error')
        else:
            # Create a new playlist for the logged-in user
            new_playlist = Playlist(name=playlist_name, user_id=user.id)
            db.session.add(new_playlist)
            db.session.commit()

            # Associate selected songs with the playlist
            for song_id in selected_songs:
                song = Song.query.get(song_id)
                if song:
                    new_playlist.songs.append(song)

            db.session.commit()

            flash('Playlist created successfully!', 'success')
            return redirect(url_for('views.userDashboard'))
    # Provide a list of all songs for the user to select from
    all_songs = Song.query.all()
    return render_template('create_playlist.html', all_songs=all_songs, user = user)

@views.route('/playlist_details/<int:playlist_id>')
def playlist_details(playlist_id):
    playlist = Playlist.query.get_or_404(playlist_id)
    return render_template('playlist_details.html', playlist=playlist)


# -------------------------Creator area--------------------------------------------------------------------------------------------------------
@views.route('/creator/become_creator', methods=['GET', 'POST'])
@login_required
def become_creator():
    user = current_user
    if request.method == 'POST':
        is_creator = bool(int(request.form.get('isCreator')))
        current_user.is_creator = is_creator
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('views.userDashboard'))
    return render_template('/creator/become_creator.html', user=user)

ALLOWED_EXTENSIONS = {'mp3', 'wav', 'ogg', 'mp4', 'm4a'}  # Define the allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@views.route('/creator/upload_song', methods=['GET', 'POST'])
@login_required 
def upload_song():
    if request.method == 'POST':
        song_title = request.form.get('songTitle')
        lyrics = request.form.get('lyrics')

        audio_file = request.files['audio_file']  # Get the uploaded audio file

        if audio_file.filename == '':
            flash('Please upload a song file.', 'error')
            return redirect(url_for('views.upload_song'))

        if audio_file and allowed_file(audio_file.filename):
            filename = secure_filename(audio_file.filename)
            audio_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))  # Save the audio file

            new_song = Song(title=song_title, artist=current_user.first_name, lyrics=lyrics, user_id=current_user.id)
            # Associate the audio file path with the song
            new_song.audio_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            db.session.add(new_song)
            db.session.commit()

            flash('Song uploaded successfully!', 'success')
            return redirect(url_for('views.creator_dashboard'))

        flash('Invalid file type for song upload.', 'error')

    return render_template('/creator/upload_song.html')


@views.route('/creator/dashboard', methods=['GET', 'POST'])
@login_required
def creator_dashboard():
    if current_user.is_creator: 
        num_uploads = Song.query.filter_by(user_id=current_user.id).count()
        uploaded_songs = Song.query.filter_by(user_id=current_user.id).all()
        return render_template('/creator/dashboard.html', user=current_user, num_uploads=num_uploads, uploaded_songs=uploaded_songs)
    flash('You are not a creator.', 'error')
    return redirect(url_for('views.userDashboard')) 

@views.route('/creator/delete_uploaded_song/<int:song_id>', methods=['POST'])
@login_required
def delete_uploaded_song(song_id):
    song = Song.query.get(song_id)
    if song:
        if song.user_id == current_user.id:
            db.session.delete(song)
            db.session.commit()
            flash('Song deleted successfully!', 'success')
        else:
            flash('You are not authorized to delete this song.', 'error')
    else:
        flash('Song not found.', 'error')
    return redirect(url_for('views.creator_dashboard'))


# -------------------------END OF VIEWS--------------------------------------------------------------------------------------------------------