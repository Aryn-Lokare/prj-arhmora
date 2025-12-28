import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myproject.settings')
django.setup()

from django.contrib.auth.models import User
from django.db import IntegrityError, DatabaseError
# Import signal to ensure it runs
from api.models import Profile

try:
    print("Attempting to create user...")
    # Use a new username to avoid integrity error
    import uuid
    uid = str(uuid.uuid4())[:8]
    username = f"debug_user_{uid}"
    email = f"debug_{uid}@test.com"
    
    user = User.objects.create_user(username, email, 'pass')
    print("User created successfully!")
    print(f"User ID: {user.id}")
    
    # Verify profile creation
    if hasattr(user, 'profile'):
        print(f"Profile created: {user.profile}")
    else:
        print("WARNING: Profile NOT created")
        
except Exception as e:
    print("\nXXX ERROR OCCURRED XXX")
    print(f"Error Type: {type(e).__name__}")
    print(f"Error Message: {e}")
    print("XXX END ERROR XXX\n")
