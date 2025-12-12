import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'securefiles.settings')
django.setup()

from accounts.models import CustomUser, UserProfile
from files.crypto_utils import generate_rsa_key_pair

def create_missing_profiles():
    users_without_profile = []
    
    for user in CustomUser.objects.all():
        try:
            profile = UserProfile.objects.get(user=user)
            print(f"✓ User {user.username} already has a profile")
        except UserProfile.DoesNotExist:
            users_without_profile.append(user)
            print(f"✗ User {user.username} is missing a profile")
    
    if users_without_profile:
        print(f"\nCreating profiles for {len(users_without_profile)} users...")
        for user in users_without_profile:
            try:
                private_key, public_key = generate_rsa_key_pair()
                
                UserProfile.objects.create(
                    user=user,
                    rsa_public_key=public_key,
                    rsa_private_key=private_key
                )
                
                # Update user model
                user.public_key = public_key
                user.private_key = private_key
                user.save()
                
                print(f"✓ Created profile for {user.username}")
            except Exception as e:
                print(f"✗ Error creating profile for {user.username}: {e}")
    else:
        print("\nAll users already have profiles!")

if __name__ == '__main__':
    create_missing_profiles()