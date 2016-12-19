from google.appengine.ext import db

from main import make_pass_hash, valid_pw

## This code contains the user model


## Saving user info
class User(db.Model):
    username = db.StringProperty(required = True)
    pass_hash = db.StringProperty(required = True)
    email = db.StringProperty()
    like = db.StringProperty()

    @classmethod
    def check_name(cls, username):
        ##Gql --> (Select * From User where name = name)
        u = User.all().filter('username = ', username).get()
        return u

## Creates an object of User
    @classmethod
    def register (cls, username, password, email = None):
        pass_hash = make_pass_hash(username, password)
        return User(username = username, pass_hash = pass_hash, email = email)


## Gets user by id from db
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)


## Login user after they have registered. This route is from login page
    @classmethod
    def login(cls, username, password):
        u = User.check_name(username)
        if u and valid_pw(username, password, u.pass_hash):
            return u


## Check to see if user liked a post

    @classmethod
    def liked_post(cls, uid, post_id):
        u = User.by_id(uid)
        return str(post_id) in str(u.like)