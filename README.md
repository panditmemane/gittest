# Requirements

Be sure you have the following working:

- Python 3.7.9
- python virtualenv
- postgresql 9.6.19
- django 3.1.7


# Enviroment setup

In the neeri_recruitment_portal directory create local_settings.py to extend the default setup.
You want to set up at least the DATABASES. You need to manually create the database in postgres (eg `createdb neeri-live`) and grant proper access.

Create and activate virtualenv. 

    python3 -m venv myenv
    
    source ../venv/bin/activate

In project directory call

    pip3 install -r requirements.txt

# Running server

    ./manage.py runserver


# Git

Keep git clean. Never commit things that are not the source code (sass cache, css, db dump etc.). Keep commits small and descriptive.

'main' branch is the main development branch.

# Test

Use pytest to test your python code.


# Directory structure

- neeri_recruitment_portal - entry point for the wsgi server, it should contain only the site configuration and other apps inclusions
- static - site wide static files, by convention we're not using app level static files
    - static - that's where the files go after running `./manage.py collectstatic`, you won't need it at all, it's just used as during one step of deployment
    - media - uploaded/generated files.

Module description is in settings.INSTALLED_APPS.

Always nest static files in the directory name the same to a relevant app.
Eg. lets say you want to add file for "document" app. You can create a file `static/document/user_id/image.png`

