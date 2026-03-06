
import os
import django
from django.db import connection

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myproject.settings')
django.setup()

def check_schema():
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT column_name, is_nullable, column_default
            FROM information_schema.columns 
            WHERE table_name = 'api_scanhistory' 
            AND column_name IN ('error_message', 'active_payload')
        """)
        rows = cursor.fetchall()
        for row in rows:
            print(f"COL: {row[0]}, Nullable: {row[1]}, Default: {row[2]}")

if __name__ == "__main__":
    check_schema()
