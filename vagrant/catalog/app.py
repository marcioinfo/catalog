from flask import Flask, render_template, request, redirect, jsonify, url_for, flash, abort, g
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from catalogModel import Base, Catalog, CatalogItem, User
from flask import session as login_session
from flask import session as user_session
from flask import make_response
import random
import string
import httplib2
import json
import requests
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import os
from flask_httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()
from flask_mail import Message, Mail


SCOPES="profile openid email"
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
ACCESS_TOKEN_URI = 'https://www.googleapis.com/oauth2/v4/token'
AUTHORIZATION_URL = 'https://accounts.google.com/o/oauth2/v2/auth?access_type=offline&prompt=consent'
AUTHORIZATION_SCOPE = 'openid email profile'

AUTH_REDIRECT_URI = os.environ.get("FN_AUTH_REDIRECT_URI")
BASE_URI = os.environ.get("FN_BASE_URI")
CLIENT_ID = os.environ.get("FN_CLIENT_ID")
CLIENT_SECRET = os.environ.get("FN_CLIENT_SECRET")
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

API_SERVICE_NAME = 'drive'
API_VERSION = 'v2'

app = Flask(__name__)


engine = create_engine('postgresql://vagrant:Nov-2018@localhost:5432/catalog')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

CLIENT_SECRETS_FILE = 'client_secrets.json'
with open(CLIENT_SECRETS_FILE, 'r') as f:
    json_data = json.load(f)

APPLICATION_NAME = "Category Store"

checkpass =[];
@app.route("/singapp", methods=['GET', 'POST'])
def singin():
    if request.method == 'POST':
        checkpass = request.form['password']
        checkuser = request.form['email']

        if checkpass is None or checkuser is None:
            abort(401)  # missign argument

        if session.query(User).filter_by(email=checkuser).first() is not None:
            abort(400)  # Existing User

        newUser = User(name=request.form['name'], email=request.form['email'], password_hash=request.form['password'])
        session.add(newUser)
        session.commit()
        user = session.query(User).filter_by(email=user_session['email']).one()
        login_session['name'] = user.name
        return render_template('newuser.html')
    else:
        return render_template('newuser.html')



@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print ("access token received %s " % access_token)


    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]


    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange we have to
        split the token first on commas and select the first index which gives us the key : value
        for the server access token then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '').decode('utf-8')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output



@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"




@app.route('/login')
def loginUser():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/authorize')
def authorize():
  # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES)

  # The URI created here must exactly match one of the authorized redirect URIs
  # for the OAuth 2.0 client, which you configured in the API Console. If this
  # value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch'
  # error.
  flow.redirect_uri = url_for('oauth2callback', _external=True)

  authorization_url, state = flow.authorization_url(
      # Enable offline access so that you can refresh an access token without
      # re-prompting the user for permission. Recommended for web server apps.
      access_type='offline',
      # Enable incremental authorization. Recommended as a best practice.
      include_granted_scopes='true')

  # Store the state so the callback can verify the auth server response.
  login_session['state'] = state

  return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
  # Specify the state when creating the flow in the callback so that it can
  # verified in the authorization server response.
  state = login_session['state']

  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
  flow.redirect_uri = url_for('oauth2callback', _external=True)

  # Use the authorization server's response to fetch the OAuth 2.0 tokens.
  authorization_response = request.url
  flow.fetch_token(authorization_response=authorization_response)

  # Store credentials in the session.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.

  credentials = flow.credentials
  oauth2_client = googleapiclient.discovery.build(
      'oauth2', 'v2',
      credentials=credentials)
  ans = oauth2_client.userinfo().get().execute()
  login_session['credentials'] = credentials_to_dict(credentials)

  user_session['username'] = ans['name']
  user_session['picture'] = ans['picture']
  user_session['email'] = ans['email']

  # see if user exists, if it doesn't make a new one
  user_id = getUserID(ans["email"])
  if not user_id:
      user_id = createUser(user_session)
  user_session['user_id'] = user_id
  user_session['provider'] = 'google'

  flash("you are now logged in as %s" % user_session['username'])

  return redirect(url_for('showCategories'))


def createUser(login_session):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    newUser = User(name=user_session['username'], email=user_session[
                   'email'], picture=user_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=user_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}

@app.route('/revoke')
def revoke():
  if 'credentials' not in login_session:
    return ('You need to <a href="/authorize">authorize</a> before ' +
            'testing the code to revoke credentials.')

  credentials = google.oauth2.credentials.Credentials(
    **login_session['credentials'])

  revoke = requests.post('https://accounts.google.com/o/oauth2/revoke',
      params={'token': credentials.token},
      headers = {'content-type': 'application/x-www-form-urlencoded'})

  status_code = getattr(revoke, 'status_code')

  if status_code == 200:

    return (status_code)
  else:
    return('An error occurred')


@auth.verify_password
def verify_password(email_or_token, *password):
    user_id = User.verify_auth_token(email_or_token)
    if user_id:
        user = session.query(User).filter_by(id=user_id).one()
    else:
        user = session.query(User).filter_by(email=email_or_token).first()
    if not user or not user.verify_password(password):
        return False
    g.user = user
    return True


def send_reset_email(user):
    token = user.generate_auth_token()
    msg = Message('Password Reset Request',
                  sender='noreply@demo.com',
                  recipients=[user.email])
    msg.body = f"""To reset your password, visit the following link:{url_for('reset_token', token=token, _external=True)} If you did not make this request then simply ignore this email and no changes will be made."""
    Mail.send(msg)


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
       email = request.form['email']

    if email:
        user = session.query(User).filter_by(email=email).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login.html'))
    return render_template('login.html')




@app.route('/reset_password/<int:token>', methods=['GET', 'POST'])
def reset_token(token):
    if request.method == 'POST':
        if 'username' in login_session:
            return redirect(url_for('showCategories'))
        else:
            user_id = verify_password(token)
            if user_id is None:
                flash('That is an invalid or expired token', 'warning')
                return redirect(url_for('reset_request'))

            if request.form['password']:
                user = getUserInfo(user_id)
                user.password_hash = User.hash_password(request.form['password'])
                session.add(user)
                session.commit()
                return redirect(url_for('singin'))
    else:
        render_template('reset_password.html', token=token)


@app.route('/applogin', methods=['GET', 'POST'])
def applogin():
    erro = ''
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if email is None or password is None:
            erro = 'missign argument'
        data = session.query(User).filter_by(email=email).first()
        if data:
            erro = 'Existing User'
        if verify_password(email, password):
            login_session['provider'] = "APP"
            login_session['username'] = data.name
            flash("you are now logged in as %s" % login_session['username'])
            return redirect(url_for('showCategories'))
        else:
            erro = 'Incorrect Password try again'
            return erro
    else:
        return render_template('login.html')


@app.route("/usersingin", methods=['GET', 'POST'])
def newUser():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['user-email']
        password = request.form['user-pass']
        if email is None or password is None:
            abort(401) # missign argument
        if session.query(User).filter_by(email=email).first() is not None:
            abort(400) # Existing User
        user = User(email=email, name=name)
        user.hash_password(password)
        session.add(user)
        session.commit()
        flash("you are now Registered")
        return redirect(url_for('applogin'))
    else:
        return render_template('login.html')




@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            revoke()
            del user_session['username']
            del user_session['email']
            del user_session['picture']
            del user_session['user_id']
            del user_session['provider']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        if login_session['provider'] == 'APP':
            del user_session['username']
            del user_session['provider']
            return redirect(url_for('showCategories'))
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCategories'))



    else:
        flash("You were not logged in")
        return ("You were not logged in")



@app.route("/")
@app.route("/catalog/showcatalog")
def showCategories():
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    categories = session.query(Catalog).order_by(asc(Catalog.name))
    return render_template('showCategories.html', categories=categories)


@app.route("/catalog/showItemCategory/<int:catag_id>/")
def showItemsCategory(catag_id):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    catagoryItems = session.query(CatalogItem).filter_by(catalog_id=catag_id).all()
    catalogitem = session.query(Catalog).filter_by(id=catag_id).one()

    return render_template('showItemsCategory.html', catagoryItems=catagoryItems, catalogitem=catalogitem)


@app.route("/catalog/showItem/<int:item_id>/item")
def showItem(item_id):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    catagoryItems = session.query(CatalogItem).filter_by(id=item_id).one()
    return render_template('showItem.html', catagoryItems=catagoryItems)



@app.route("/catalog/addBrands", methods=['GET', 'POST'])
def addBrands():
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    if request.method == 'POST':
        addBrand=Catalog(name=request.form['name'])
        session.add(addBrand)
        session.commit()
        return redirect(url_for('showCategories'))
    else:
        return render_template('addBrands.html')

@app.route("/catalog/deleteCategory/<int:catag_id>/", methods=['GET', 'POST'])
def deleteCategory(catag_id):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    deleteCatag = session.query(Catalog).filter_by(id=catag_id).one()
    if request.method == 'POST':
        deleteitem = session.query(CatalogItem).filter_by(catalog_id=catag_id).delete()
        session.delete(deleteCatag)
        session.commit()
        return redirect(url_for('showCategories'))
    else:
        return render_template("deleteCategory.html", deleteCatag=deleteCatag)


@app.route("/catalog/editCategory/<int:catag_id>/", methods=['GET', 'POST'])
def editCategory(catag_id):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    editCategory = session.query(
        Catalog).filter_by(id=catag_id).one()
    if request.method == 'POST':
        editCategory.name = request.form['name']
        session.add(editCategory)
        session.commit()

        return redirect(url_for('showItemsCategory', catag_id=catag_id))
    else:
        return render_template('updateCategory.html', editCategory=editCategory)


@app.route("/catalog/addItem/<int:catag_id>/", methods=['GET', 'POST'])
def addItem(catag_id):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    catalogitem = session.query(Catalog).filter_by(id=catag_id).one()
    if request.method == 'POST':
        newItem = CatalogItem(name=request.form['name'], description=request.form['description'], price=request.form['price'], image_name=request.form['image_name'], catalog_id=catag_id)
        session.add(newItem)
        session.commit()
        return redirect(url_for('showItemsCategory', catag_id=catag_id))
    else:
        return render_template('addItem.html', catalogitem=catalogitem)


@app.route("/catalog/update/<int:catag_id>/item/<int:item_id>", methods=['GET', 'POST'])
def updateItem(catag_id, item_id):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    category = session.query(Catalog).filter_by(id=catag_id).one()
    updateitem = session.query(CatalogItem).filter_by(id=item_id).one()
    if request.method == 'POST':
        if request.form['name']:
            updateitem.name = request.form['name']

        if request.form['description']:
            updateitem.description = request.form['description']

        if request.form['price']:
            updateitem.price = request.form['price']

        if request.form['image_name']:
            updateitem.image_name = request.form['image_name']

        session.add(updateitem)
        session.commit()
        return redirect(url_for('showItemsCategory', catag_id=catag_id))
    else:
        return render_template('updateItem.html', updateitem=updateitem)


@app.route("/catalog/delete/<int:item_id>/", methods=['GET', 'POST'])
def deleteItem(item_id):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    deleteitem = session.query(CatalogItem).filter_by(id=item_id).one()
    if request.method == 'POST':
        session.delete(deleteitem)
        session.commit()
        return redirect(url_for('showItemsCategory', catag_id=deleteitem.catalog_id))
    else:
        return render_template("deleteitem.html", deleteitem=deleteitem)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)