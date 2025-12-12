import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'securefiles.settings')
django.setup()

from files.models import SecureFile, FileShare
from accounts.models import UserProfile
from files.crypto_utils import decrypt_rsa, encrypt_rsa

def fix_all_shares():
    """Fix all file shares by re-encrypting AES keys properly"""
    shares = FileShare.objects.all()
    fixed_count = 0
    
    for share in shares:
        try:
            print(f"\nFixing share #{share.id}:")
            print(f"  File: {share.file.original_filename}")
            print(f"  Owner: {share.file.owner.username}")
            print(f"  Shared with: {share.shared_with.username}")
            
            # Get owner's profile
            owner_profile = UserProfile.objects.get(user=share.file.owner)
            
            # Get original AES key
            encrypted_aes_key = bytes.fromhex(share.file.encrypted_aes_key)
            original_aes_key = decrypt_rsa(encrypted_aes_key, owner_profile.rsa_private_key)
            print(f"  Original AES key retrieved")
            
            # Get shared user's profile
            shared_user_profile = UserProfile.objects.get(user=share.shared_with)
            
            # Re-encrypt with shared user's public key
            re_encrypted_aes_key = encrypt_rsa(original_aes_key, shared_user_profile.rsa_public_key)
            
            # Update the share
            share.encrypted_aes_key = re_encrypted_aes_key.hex()
            share.save()
            
            print(f"  ✓ Share fixed")
            fixed_count += 1
            
        except Exception as e:
            print(f"  ✗ Error fixing share: {e}")
    
    print(f"\nTotal shares fixed: {fixed_count}/{shares.count()}")
    return fixed_count

if __name__ == '__main__':
    fix_all_shares()