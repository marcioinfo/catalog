# Item-Catalog-Application


# Project Overview
This application provides a list of items within a variety of categories as well as provide a user authentication system. Users will have the ability to post, edit and delete their own items.


# Prerequisites

You will need to install these following application in order to make this code work.
- Unix-style terminal(Windows user please download and use Git Bash terminal)
- [VirtualBox](https://github.com/marcioinfo/fullstack-nanodegree-vm)
- Vagrant
- Postgresql instance



# Getting Started
You can clone or download this project via GitHub to your local machine.
Modern web applications perform a variety of functions and provide amazing features and utilities to their users; but deep down, it’s really all just creating, reading, updating and deleting data. In this projec building dynamic websites with persistent data storage to create a web application that provides a compelling service to your users.

## Security Requirement

You will also need to download these following files to make it work.
- fb_client_secrets.json
- client_secrets.json

To run the application, use the secret keys of google and facebook available in the project folder, they will be removed once the code is reviewed.
if you want to continue using the app you will need to register a new secret key with google and facebook.


Google APIs and Facebook use the OAuth 2.0 protocol for authentication and authorization. See the documentation: [Google Auth 2.0](https://developers.google.com/identity/protocols/OAuth2) and
Facebook [Auth.20](https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow/)



## DataBase
You need to create the database in order to run the apps, I used Postgree but feel free to implement in another SGBD, the file lotsofmenu.py contains some data to popular the database tables set up in the catalogModel.py file.

```
engine = create_engine('postgresql://user:password@localhost:port/dbname')

```
import the CSV files into your tables and get all data example. This app renders images stored in a static folder which the reference names are stored on the table item_catalog.

[Check import CSV ](http://www.postgresqltutorial.com/import-csv-file-into-posgresql-table/)


## Reset Password function

The password recovery function uses the Gmail mail server, the user and password are defined hardcode in the App.py file code, I will remove it once the code is reviewed, I recommend you to use an environment variable store this value.


Download the VM [here](https://pages.github.com/):
Find the catalog folder and replace it with the content of this current repository, by either downloading or cloning it from Here.


## API JSON

The, category list page and item details page show thier JSON end points, which can be created accessing the folowing URL

All Category List
* http://localhost:5000/categories/JSON

Category details
* http://localhost:5000/categories/catalog_id/items/JSON

All Items
* http://localhost:5000/categories/items/JSON

Launch the Vagrant VM using the command:
 
```
   vagrant up
  $ vagrant ssh
```

Run your application within the VM:

```
$ python /vagrant/catalog/app.py
```

Access and test your application by visiting ```http: // localhost: 5000```
