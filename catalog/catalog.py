from flask import Flask, render_template, request, redirect, jsonify, url_for
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Catalog, Item, User
from datetime import datetime
from flask import session as login_session
import random
import string
from functools import wraps

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from flask import flash
app = Flask(__name__)


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "logs"


engine = create_engine('sqlite:///catalogitems.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(
        random.choice(
            string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """
    Gathers data from Google Sign In API and places it inside a session variable.
    """
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'

    flash("you are now logged in as %s" % login_session['username'])
    return output


@app.route('/gdisconnect')
def gdisconnect():
    """
    disconnect from google
    """

    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' \
        % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        return redirect(url_for('showCategories'))
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# user
def createUser(login_session):
    """
    create a user if there is none in the database
    """
    newUser = User(name=login_session['username'], email=login_session[
                   'email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one_or_none()
    return user.id


def getUserInfo(user_id):
    """
    get user and return it
    """
    user = session.query(User).filter_by(id=user_id).one_or_none()
    return user


def getUserID(email):
    """
    get user's id and return it
    """
    try:
        user = session.query(User).filter_by(email=email).one_or_none()
        return user.id
    except:
        return None

def login_required(func):
    """
    checks if the user is login
    """
    @wraps(func) # this requires an import
    def wrapper():
        if 'username' not in login_session:
            return redirect('login')
        else:
            func()
    return wrapper

# JSON endpoint
@app.route('/catalog/<int:catalog_id>/JSON')
def catItemJSON(catalog_id):
    """
    gets the item json from a catalog and return it
    """
    catalog = session.query(Catalog).filter_by(id=catalog_id).one_or_none()
    itemss = session.query(Item).filter_by(catalog_id=catalog_id).all()
    it = []
    for its in itemss:
        ite = {
            "cat_id": its.catalog.id,
            "description": its.description,
            "id": its.id,
            'user_id': its.user_id,
            "title": its.name
            }
        it.append(ite)
    return it


@app.route('/catalog/catalog.json')
def categoriesJSON():
    """
    gathers all the categories and items into json and
    calls catItemJSON to get the item json
    """
    catalog = session.query(Catalog).all()
    items = session.query(Item).all()
    data = []
    for c in catalog:
        cat = {"id": c.id, "name": c.name}
        for i in items:
            if c.id == i.catalog_id:
                item = {"items": catItemJSON(c.id)}
                cat.update(item)
                break
        data.append(cat)
    return jsonify(Categories=[data])


# Show all categories
@app.route('/')
@app.route('/catalog/')
def showCategories():
    """
    the sending categories and item to categories.html or home page
    """
    categories = session.query(Catalog).all()
    item = session.query(Item).all()
    return render_template('categories.html', categories=categories, item=item)


# Show a catalog item
@app.route('/catalog/<string:catalog_name>/')
@app.route('/catalog/<string:catalog_name>/item/')
def showItem(catalog_name):
    """
    show the item and render its to item.html
    """
    catalog = session.query(Catalog).filter_by(name=catalog_name).one_or_none()
    items = session.query(Item).filter_by(catalog_id=catalog.id).all()
    return render_template('item.html', items=items, catalog=catalog)


# Show a item description
@app.route('/catalog/<string:catalog_name>/<string:item_name>/')
def showDes(catalog_name, item_name):
    """
    shows the description of the item if the its none user
    but if the user is login it will show edit and delete in the des.html
    """
    item = session.query(Item).filter_by(name=item_name).one_or_none()
    if login_session['user_id'] == item.user_id:
        u = True
    else:
        u = False
    return render_template('des.html', item=item, u=u)


@login_required
@app.route(
    '/catalog/<string:catalog_name>/item/new/', methods=['GET', 'POST'])
def newItem(catalog_name):
    """
    checks if the user is login with the @login_required above @app.route
    add new Item to the database
    """
    if request.method == 'POST':
        catalog = session.query(Catalog).filter_by(name=catalog_name).one_or_none()
        newItem = Item(name=request.form['name'], description=request.form[
            'description'], time=datetime.now(),
            catalog_id=catalog.id,
            user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()

        return redirect(url_for('showItem', catalog_name=catalog_name))
    else:
        return render_template('newitem.html', catalog_name=catalog_name)

    return render_template('newItem.html', catalog=catalog)


# Edit a item
@login_required
@app.route('/catalog/<string:catalog_name>/item/<string:item_name>/edit',
           methods=['GET', 'POST'])
def editItem(catalog_name, item_name):
    """
    checks if the user is login with the @login_required above @app.route
    edit item only if it was created by the same user
    if not return back to home page
    """
    editedItem = session.query(Item).filter_by(name=item_name).one_or_none()
    if editedItem.user_id != login_session['user_id']:
    flash('You are not authorized to edit this item.')
    return redirect('/')
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        session.add(editedItem)
        session.commit()
        return redirect(url_for('showItem', catalog_name=catalog_name))
    else:

        return render_template(
            'edititem.html',
            catalog_name=catalog_name,
            item_name=item_name,
            item=editedItem)


# Delete a item
@login_required
@app.route('/catalog/<string:catalog_name>/item/<string:item_name>/delete',
           methods=['GET', 'POST'])
def deleteItem(catalog_name, item_name):
    """
    checks if the user is login with the @login_required above @app.route
    delete the Item only if it was created by the same user
    if not return back to home page
    """
    itemToDelete = session.query(Item).filter_by(name=item_name).one_or_none()
    if editedItem.user_id != login_session['user_id']:
        flash('You are not authorized to edit this item.')
        return redirect('/')
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        return redirect(url_for('showItem', catalog_name=catalog_name))
    else:
        return render_template('deleteitem.html', item=itemToDelete)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
