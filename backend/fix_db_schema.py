
import os
import django
from django.db import connection

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myproject.settings')
django.setup()

def fix_schema():
    with connection.cursor() as cursor:
        print("Dropping NOT NULL constraints...")
        # Make all suspicious columns nullable
        columns_to_fix = ['last_heartbeat', 'ai_priority_result', 'active_payload', 'error_message']
        
        for col in columns_to_fix:
            try:
                print(f"Fixing {col}...")
                cursor.execute(f"ALTER TABLE api_scanhistory ALTER COLUMN {col} DROP NOT NULL")
            except Exception as e:
                print(f"Could not fix {col}: {e}")
        
        print("Done. Verifying...")
        cursor.execute(f"SELECT column_name, is_nullable FROM information_schema.columns WHERE table_name = 'api_scanhistory' AND column_name IN ({','.join(['%s']*len(columns_to_fix))})", columns_to_fix)
        rows = cursor.fetchall()
        for row in rows:
            print(f"{row[0]}: Nullable={row[1]}")

if __name__ == "__main__":
    fix_schema()
