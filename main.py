import os
import webapp2

## rendering of HTML files
import jinja2


##read regular expressions
import re



## for hashing user id and pass
import random
import hashlib
import hmac
import string


## import db to save info
from google.appengine.ext import db








## for adding a time delay for DB to update
import time

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
##autoescape to autoescape html characters submitted
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = True)

## * - positional arguments
## ** - keyword arguments




## make salt: random string to add with name and password to make hash
def make_salt():
    return ''.join(random.choice(string.letters) for i in range (0, 5))


## making hash of name pass and salt. salt stored as well
def make_pass_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name+pw+salt).hexdigest()
    return '%s|%s' %(salt, h)


##check if password is valid
def valid_pw(name, password, h):
    salt = h.split('|')[0]
    return h == make_pass_hash(name, password, salt)



##def make_pass_hash(pw):
##    h = hashlib.sha256(pw).hexdigest()
##    return '%s' % (h)


secret = 'hello'



def make_secure_cookie(pw):
    return '%s|%s' % (pw, hmac.new(secret, pw).hexdigest())



def check_secure_cookie(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_cookie(val):
        return val




USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)



class Handler(webapp2.RequestHandler):
    def write(self, *template, **params):
        self.response.out.write(*template, **params)
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    def render (self, template, **args):
        self.write(self.render_str(template, **args))

## This function uses the hash function on the password and sets
## the cookie to that
    def set_cookie(self, user_id, userid):
        cookie_val = make_secure_cookie(userid)
        username = str(user_id)
        self.response.headers.add_header('Set-Cookie','%s = %s; Path = /'
                                        %(username, cookie_val))



    def read_secure_cookie(self, username):
        cookie_val = self.request.cookies.get(username)
        return cookie_val and check_secure_cookie(cookie_val)





## Implement an initialize function that checks cookie for user id.
## Once checked and found also checks db. If both are found ....
## Other functions using handler now have access to User model in db
## and its properties

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


    def login(self, user):
        self.set_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie','user_id=; Path = /')


##Import models, after loading all the functions that the models use.

from users import *

from comments import *

from blogs import *





class BlogMainPage(Handler):
    ## Populates main blog page with ten most recent posts
    def get(self):
        if self.user:
            user = self.user
            posts = db.GqlQuery('Select * From blog_post ORDER BY created \
                Desc limit 10')
            self.render('all-blog-entries.html', posts = posts, user=user)
        else:
            posts = db.GqlQuery('Select * From blog_post ORDER BY created \
                Desc limit 10')
            self.render('all-blog-entries-unauth.html', posts=posts)


    ## Handling the like POST of users

class LikePost(Handler):
    def get(self):
        user=self.user
        uid = user.key().id()
        post_id = self.request.get("post_id")
        post=blog_post.get_by_id(int(post_id))


    ## Check to see if user already liked post with liked_post classmethod
    ## First if statement initializes user.like datastore
        if not user.like:
            post.likes=post.likes+1
            user.like=str(post_id) + ","
        elif User.liked_post(uid, post_id):
            user.like = user.like.replace(str(post_id) + ",","")
            post.likes=post.likes - 1
        else:
            user.like = user.like + str(post_id) + ','
            post.likes=post.likes + 1

        user.put()
        post.put()

        self.redirect('/redirect/1/blog')








## New post handler.

class NewPost(Handler):
    def get(self):
        if self.user:
            self.render('blog-entry-page.html')
        else:
            self.redirect('/login')

    def post(self):
        if not self.user:
            self.redirect('/login')
        author = self.user.username
        title = self.request.get('title')
        entry = self.request.get('entry')
        if title and entry:
            ##Save blog post
            p = blog_post(title = title, entry = entry,
                         author = author, likes=0)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = 'Please enter Title and Post'
            self.render('blog-entry-page.html', error = error,
                        title = title, entry = entry)







## Page displaying user blog posts. Users can also comment on blog posts.
class PostPage(Handler):
    def get(self, post_id):
        key = db.Key.from_path('blog_post', int(post_id))
        post = db.get(key)
        ##Check to see if post exists and handles error if it does not
        if post:
            author=blog_post.get_by_id(int(post_id)).author
            postId = int(post_id)
            userId = self.user.key().id()
            comments = Comments.all().filter("postId =", postId).order("created")
            self.render('new_post_page.html', post = post, author=author,
                        comments=comments, userId = userId)
        else:
            self.redirect('/errorhandler/2/blog')


## Handling Post requests for comments on user blog posts
## post_id comes from the URL
    def post(self, post_id):
        if not self.user:
            self.redirect('/login')
        key = db.Key.from_path('blog_post', int(post_id))
        post = db.get(key)
        ##Check to see if post exists and handles error if it does not
        if post:
            postId = int(post_id)
            userId = self.user.key().id()
            author = self.user.username
            comment = self.request.get("comment")
            if comment:
                comment = Comments(postId=postId, userid=userId, author=author,
                                    comment=comment)
                comment.put()
                time.sleep(1)
                comments = Comments.all().filter("postId =", postId).order("created")
                self.render("new_post_page.html",
                            post = post,
                            author=author,
                            userId = userId,
                            comments=comments)
            else:
                comments = Comments.all().filter("postId =", postId).order("created")
                self.render("new_post_page.html",
                            post = post,
                            author=author,
                            comments=comments,
                            userId = userId,
                            error="Please enter comment before submitting")
        else:
            self.redirect('/errorhandler/2/blog')





## This class serves the display content for editing a comment
class EditComment(Handler):
    def get(self, commentId):
        comment=Comments.get_by_id(int(commentId))
        ## Check if comment else handle error. Also check that user accessing created comment
        if comment:
            if not self.user:
                self.redirect('/login')
            if self.user.username != comment.author:
                self.redirect('/unauth/2/blog')
            else:
                self.render("edit-comment.html", comment=comment)
        else:
            self.redirect('/errorhandler/2/blog')





    def post(self, commentId):
        comment=Comments.get_by_id(int(commentId))
        ## Check if comment else handle error
        if comment:
            ## getting post info for the redirect URL
            post = comment.postId
            purpose = self.request.get("purpose")
            ## get data from request
            entry = self.request.get("comment")
            if "delete" in purpose:
                if not self.user:
                    self.redirect('/login')
                else:
                    comment.delete()
                    time.sleep(1)
                    self.redirect('/blog/%s' % (post))
            else:
                if not self.user:
                    self.redirect('/login')
                else:
                    if entry:
                        comment.comment=entry
                        comment.put()
                        time.sleep(1)
                        self.redirect('/blog/%s' % (post))
        else:
            self.redirect('/errorhandler/2/blog')










## Editing and deleting blog posts
class EditPage(Handler):
    def get(self, post_id):
        key = db.Key.from_path('blog_post', int(post_id))
        post = db.get(key)
        ## Check to see if blog post exists, else redirect
        if post:
            ##Check to see user owns blog post else redirect unauth
            if self.user.username == post.author:
                self.render('edit-content.html', post = post)
            else:
                self.redirect('/unauth/2/blog')
        else:
            self.redirect('/errorhandler/2/blog')





## Post request depends on whether user is deleting or editing comment
## post_id comes from the URL

    def post(self, post_id):
        post = blog_post.get_by_id(int(post_id))
        ## Check to see if blog post exists, else redirect
        if post:
            ##Check to see user owns blog post else redirect unauth
            if self.user.username == post.author:
                purpose = self.request.get("purpose")
                title = self.request.get("title")
                entry = self.request.get("entry")

                if "delete" in purpose:
                ## Check to see if valid user
                    if not self.user:
                        self.redirect('/login')
                    else:
                        post.delete()
                        self.redirect('/redirect/1/blog')
                else:
                ## Check to see if valid user
                    if not self.user:
                        self.redirect('/login')
                    else:
                        if title and entry:
                            post.title= title
                            post.entry=entry
                            post.put()
                            self.redirect('/redirect/1/blog')
            else:
                self.redirect('/unauth/2/blog')
        else:
            self.redirect('/errorhandler/2/blog')








## Registering users and handling logging in and out
class MainPage(Handler):
    def get(self):
        self.redirect('/signup')


class sign_up(Handler):
    def get(self):
        self.render('user_signup.html')


    def post(self):
        error_present = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        verify = self.request.get('verify')
        self.email = self.request.get('email')



        params = dict(username = self.username,
                      email = self.email)


        if not valid_username(self.username):
            params ['error_username'] = 'That was not a valid username.'
            error_present = True

        if not valid_password(self.password):
            params['error_password'] = "That was not a valid password."
            error_present = True

        elif self.password != verify:
            params['error_verify'] = "Your passwords didn't match."
            error_present = True

        if not valid_email(self.email):
            params['error_email'] = "That was not a valid email."
            error_present = True

        if error_present:
            self.render('user_signup.html', **params)
        else:
##  Register takes in sign up and after getting info runs done function
##  located in Register
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError



class Register(sign_up):
    def done(self):
        username = self.username
        password = self.password
        email = self.email
        u = User.check_name(username)
        if u:
            error = 'That username already exists'
            self.render('user_signup.html', error_username = error)
        else:
            ##self.set_cookie(self.username, self.password)
            u = User.register(username, password, email)
            u.put()

            self.login(u)
            self.redirect('/welcome')


class WelcomePage(Handler):
    def get(self):
        if self.user:
            username = self.user.username
            self.render('welcome-page.html' ,username = username)
        else:
            self.redirect('/login')



class Login(Handler):
    def get(self):
        self.render('login-form.html')
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            error = 'Invalid login'
            self.render('login-form.html', error = error)


class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/signup')




## Redirect delay page that allows for the DB to update. Please note the three
## entries in URL corresponding to input for get requests

class RedirectDelay(Handler):
    def get(self, time, page):
        page = '/'+ page
        self.render('redirectdelay.html',time=time, page=page)




## Error handler for incorrect Blog and comment post requests
class Errorhandler(Handler):
    def get(self, time, page):
        page = '/'+ page
        self.render('errorhandler.html',time=time, page=page)


## Error handler for unauthorized user edit
class Unauth(Handler):
    def get(self, time, page):
        page = '/'+ page
        self.render('unauthorized.html',time=time, page=page)










app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/welcome', WelcomePage),
    ('/signup', Register),
    ('/login', Login),
    ('/logout', Logout),
    ('/blog', BlogMainPage),
    ('/blog/newpost', NewPost),
    ('/likepost', LikePost),
    ('/edit/([0-9]+)', EditPage),
    ('/editcomment/([0-9]+)', EditComment),
    ('/errorhandler/([a-zA-Z0-9_-]+)/([a-zA-Z0-9_-]+)', Errorhandler),
    ('/unauth/([a-zA-Z0-9_-]+)/([a-zA-Z0-9_-]+)', Unauth),
    ('/redirect/([a-zA-Z0-9_-]+)/([a-zA-Z0-9_-]+)', RedirectDelay),
    ('/blog/([0-9]+)', PostPage)

], debug=True)
