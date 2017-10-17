# Item Catalog Project

This item catalog project is about listing sports items sorted by their categories for non-user to only view and users to create, update, and delete for Google accounts only.

## What you need to run this program

* python2
* flask
* sqlalchemy
* oauth2client.client
* httplib2
* json

If you wish not to install the list above install vagrant and virtualbox, after installing both [here](https://github.com/udacity/fullstack-nanodegree-vm) from udacity with all the installations.

## Steps

* Launch catalog.py in python (vagrant up and ssh if using vagrant)
* copy http://localhost:8000 to url of any web browser
* after that you the user will be within the homepage showing list of categories and items right side of categories. At the far left top will see Category link that will take you back to home page and far right is where to login by Google.

## what the program is using

* html files located within the templates folder within most of the files shows flask format use for python and css file within the static folder
* sqlite database catalogitems.py tables are:
1. User
2. Catalog
3. Item
for more info go to database_setup.py
* JSON to view the JSON endpoints click [here](http://localhost:8000/catalog/catalog.json)

There are 8 pages that are: the main page with specific category and items, a specific item that shows information about the item, creates, update, and deletes items, login, and JSON endpoint.
