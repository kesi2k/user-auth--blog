from google.appengine.ext import db


## This code contains the comments model

class Comments(db.Model):
    postId = db.IntegerProperty(required = True)
    userid = db.IntegerProperty(required = True)
    author = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    comment = db.TextProperty(required = True)