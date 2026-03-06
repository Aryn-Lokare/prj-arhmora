
import os
import django
from django.db import connection

# Setup Django environment BEFORE any other imports
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myproject.settings')
django.setup()

from django.conf import settings
print(f"DEBUG: Using Database: {settings.DATABASES['default']['NAME']} on {settings.DATABASES['default']['HOST']}:{settings.DATABASES['default']['PORT']}")

from rest_framework.test import APIRequestFactory, force_authenticate
from django.contrib.auth.models import User
from api.views import ScanView

def simulate_scan_post():
    try:
        user = User.objects.filter(username='admin').first()
        if not user:
            user = User.objects.create_superuser('admin', 'admin@example.com', 'admin')
        
        factory = APIRequestFactory()
        url = 'https://google.com'
        request = factory.post('/api/scan/', {'target_url': url}, format='json')
        force_authenticate(request, user=user)
        
        view = ScanView.as_view()
        response = view(request)
        
        print(f"Response Status: {response.status_code}")
        if response.status_code == 500:
            print(f"Error Message: {response.data.get('message')}")
        else:
            print(f"Response Data: {response.data}")
            
    except Exception as e:
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    simulate_scan_post()
