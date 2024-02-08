from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt()

db=SQLAlchemy()

# Association Table for Many-to-Many relationship between Playlist and Song
playlist_song_association = db.Table(
    'playlist_song_association',
    db.Column('playlist_id', db.Integer, db.ForeignKey('playlist.id')),
    db.Column('song_id', db.Integer, db.ForeignKey('song.id'))
)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email=db.Column(db.String(150), nullable=False)
    password=db.Column(db.String(150), nullable=False)
    first_name = db.Column(db.String(150))
    is_admin = db.Column(db.Boolean, default=False)
    is_creator = db.Column(db.Boolean, default=False)
    playlists = db.relationship('Playlist', back_populates='user')
    songs = db.relationship('Song', back_populates='user')

    def __str__(self):
        return self.first_name or "No name available"
    def update_password(self, new_password):
        self.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        db.session.commit()

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)


class Playlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', back_populates='playlists')
    songs = db.relationship('Song', secondary=playlist_song_association, back_populates='playlists')

    def delete(self):
        # Remove the playlist association with songs
        self.songs = []
        db.session.commit()
        # Delete the playlist
        db.session.delete(self)
        db.session.commit()

class Song(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    artist = db.Column(db.String(255), nullable=False)
    lyrics = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', back_populates='songs')
    playlist_id = db.Column(db.Integer, db.ForeignKey('playlist.id'))
    playlists = db.relationship('Playlist', secondary=playlist_song_association, back_populates='songs')
    audio_file_path = db.Column(db.String(255), nullable=True)

    def __repr__(self):
        return f'Song("{self.title}", "{self.artist}")'

