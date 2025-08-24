from django.db import connection

def show_user(request, username):
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE username = '%s'" % username)
