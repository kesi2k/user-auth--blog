from google.appengine.ext import db


## This code contains the blog posts model

class blog_post(db.Model):
    author=db.StringProperty(required=True)
    title = db.StringProperty(required = True)
    entry = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    likes = db.IntegerProperty(required=True)