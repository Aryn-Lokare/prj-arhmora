
import os
import django
from django.db import connection

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myproject.settings')
django.setup()

def check_schema():
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT column_name, data_type, is_nullable, column_default, ordinal_position
            FROM information_schema.columns 
            WHERE table_name = 'api_scanhistory' 
            ORDER BY ordinal_position
        """)
        rows = cursor.fetchall()
        print(f"{'Pos':<3} | {'Column Name':<20} | {'Type':<20} | {'Null':<5} | {'Default'}")
        print("-" * 80)
        for row in rows:
            print(f"{row[4]:<3} | {row[0]:<20} | {row[1]:<20} | {row[2]:<5} | {row[3]}")

if __name__ == "__main__":
    check_schema()
