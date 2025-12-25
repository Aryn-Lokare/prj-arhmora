import os
import django
from django.db import connection

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myproject.settings')
django.setup()

tables_to_drop = [
    'api_emailverificationtoken',
    'api_passwordresettoken',
    'api_profile',
    # 'api_customuser' # In case it lingers
]

with connection.cursor() as cursor:
    for table in tables_to_drop:
        try:
            print(f"Dropping {table}...")
            cursor.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
            print(f"Dropped {table}")
        except Exception as e:
            print(f"Error dropping {table}: {e}")
