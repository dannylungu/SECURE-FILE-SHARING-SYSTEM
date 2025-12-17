import os
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponse
from django.conf import settings
from .models import SecureFile, FileShare
from .forms import FileUploadForm, FileShareForm
from .crypto_utils import (
    generate_aes_key, encrypt_file_aes, decrypt_file_aes,
    encrypt_rsa, decrypt_rsa, compute_file_hash
)

@login_required
def file_upload_view(request):
    if request.user.role == 'guest':
        messages.error(request, 'Guests cannot upload files.')
        return redirect('dashboard')
    
    # Check if user has a profile
    try:
        from accounts.models import UserProfile
        user_profile = UserProfile.objects.get(user=request.user)
        has_profile = True
    except UserProfile.DoesNotExist:
        messages.error(request, 'User profile not found. Please contact administrator.')
        return redirect('dashboard')
    
    if request.method == 'POST':
        # Use the form but handle the file separately
        uploaded_file = request.FILES.get('file')
        if uploaded_file:
            try:
                print(f"\n=== DEBUG UPLOAD START ===")
                print(f"File: {uploaded_file.name}")
                print(f"User: {request.user.username}")
                
                # Read file data
                file_data = uploaded_file.read()
                print(f"Original file size: {len(file_data)} bytes")
                
                # Generate AES key
                aes_key = generate_aes_key()
                print(f"Generated AES key: {aes_key.hex()[:32]}...")
                
                # Encrypt file with AES
                encrypted_data = encrypt_file_aes(file_data, aes_key)
                print(f"Encrypted file size: {len(encrypted_data)} bytes")
                
                # Get user's RSA public key
                from accounts.models import UserProfile
                from logs.models import SecurityLog
                
                user_profile = UserProfile.objects.get(user=request.user)
                print(f"Using RSA public key from profile")
                
                # Encrypt AES key with user's RSA public key
                encrypted_aes_key = encrypt_rsa(aes_key, user_profile.rsa_public_key)
                print(f"Encrypted AES key (hex): {encrypted_aes_key.hex()[:64]}...")
                
                # Compute file hash
                file_hash = compute_file_hash(encrypted_data)
                print(f"File hash: {file_hash}")
                
                # Create SecureFile instance
                secure_file = SecureFile(
                    owner=request.user,
                    original_filename=uploaded_file.name,
                    encrypted_aes_key=encrypted_aes_key.hex(),
                    file_hash=file_hash,
                    file_size=len(encrypted_data)
                )
                
                # Save encrypted file
                file_path = f'user_{request.user.id}/{uploaded_file.name}.encrypted'
                secure_file.encrypted_file.save(file_path, uploaded_file, save=False)
                
                # Write encrypted data to file
                media_path = secure_file.encrypted_file.path
                os.makedirs(os.path.dirname(media_path), exist_ok=True)
                with open(media_path, 'wb') as f:
                    f.write(encrypted_data)
                
                secure_file.save()
                print(f"File saved with ID: {secure_file.id}")
                
                # Test decryption immediately (for debugging)
                try:
                    # Decrypt AES key
                    test_aes_key = decrypt_rsa(encrypted_aes_key, user_profile.rsa_private_key)
                    print(f"Test decryption - AES key matches: {test_aes_key == aes_key}")
                    
                    # Decrypt file
                    test_decrypted = decrypt_file_aes(encrypted_data, test_aes_key)
                    print(f"Test decryption - File matches: {test_decrypted == file_data}")
                    
                    if test_decrypted == file_data:
                        print("✓ Upload encryption test PASSED")
                    else:
                        print("✗ Upload encryption test FAILED")
                        
                except Exception as e:
                    print(f"✗ Upload encryption test ERROR: {e}")
                
                # Log the upload
                SecurityLog.objects.create(
                    user=request.user,
                    action='FILE_UPLOAD',
                    description=f'Uploaded file: {uploaded_file.name}',
                    ip_address=get_client_ip(request)
                )
                
                print("=== DEBUG UPLOAD END ===\n")
                messages.success(request, 'File uploaded and encrypted successfully!')
                return redirect('file_list')
            
            except Exception as e:
                print(f"\n=== DEBUG UPLOAD ERROR ===")
                print(f"Error: {e}")
                import traceback
                traceback.print_exc()
                print("=== DEBUG UPLOAD ERROR END ===\n")
                
                from logs.models import SecurityLog
                # Log the error
                SecurityLog.objects.create(
                    user=request.user,
                    action='FILE_UPLOAD_ERROR',
                    description=f'Upload failed for {uploaded_file.name}: {str(e)}',
                    ip_address=get_client_ip(request)
                )
                
                messages.error(request, f'Error uploading file: {str(e)}')
                # IMPORTANT: Return the render even on error
                return render(request, 'files/file_upload.html', {})
        else:
            messages.error(request, 'No file selected.')
            # IMPORTANT: Return the render even when no file is selected
            return render(request, 'files/file_upload.html', {})
    
    # GET request - show the upload form
    # This return statement was likely missing
    return render(request, 'files/file_upload.html', {})
                
            

@login_required
def file_list_view(request):
    # Get user's own files
    user_files = SecureFile.objects.filter(owner=request.user)
    
    # Get files shared with user
    shared_files = SecureFile.objects.filter(shares__shared_with=request.user)
    
    # Get all users for sharing
    from accounts.models import CustomUser
    all_users = CustomUser.objects.exclude(id=request.user.id)
    
    context = {
        'user_files': user_files,
        'shared_files': shared_files,
        'all_users': all_users,
    }
    return render(request, 'files/file_list.html', context)

@login_required
def file_download_view(request, file_id):
    secure_file = get_object_or_404(SecureFile, id=file_id)
    
    # Check permissions
    is_owner = secure_file.owner == request.user
    is_shared = FileShare.objects.filter(file=secure_file, shared_with=request.user).exists()
    
    if not is_owner and not is_shared:
        from logs.models import SecurityLog
        SecurityLog.objects.create(
            user=request.user,
            action='UNAUTHORIZED_DOWNLOAD',
            description=f'Attempted to download file: {secure_file.original_filename}',
            ip_address=get_client_ip(request)
        )
        messages.error(request, 'You do not have permission to download this file.')
        return redirect('file_list')
    
    try:
        print(f"\n=== DEBUG DOWNLOAD START ===")
        print(f"File: {secure_file.original_filename}")
        print(f"User: {request.user.username}")
        print(f"Is owner: {is_owner}")
        print(f"Is shared with user: {is_shared}")
        
        # Read encrypted file
        with open(secure_file.encrypted_file.path, 'rb') as f:
            encrypted_data = f.read()
        
        print(f"Encrypted file size: {len(encrypted_data)} bytes")
        
        # Verify file integrity
        current_hash = compute_file_hash(encrypted_data)
        print(f"Current hash: {current_hash[:32]}...")
        print(f"Stored hash: {secure_file.file_hash[:32]}...")
        
        if current_hash != secure_file.file_hash:
            from logs.models import SecurityLog
            SecurityLog.objects.create(
                user=request.user,
                action='FILE_INTEGRITY_VIOLATION',
                description=f'File integrity check failed for: {secure_file.original_filename}',
                ip_address=get_client_ip(request)
            )
            messages.error(request, 'File integrity check failed. File may have been tampered with.')
            return redirect('file_list')
        
        # Get user's RSA private key
        from accounts.models import UserProfile
        from logs.models import SecurityLog
        
        user_profile = UserProfile.objects.get(user=request.user)
        print(f"User profile found for {request.user.username}")
        
        # Determine which AES key to use
        if is_owner:
            # Use the original AES key from SecureFile
            encrypted_aes_key = bytes.fromhex(secure_file.encrypted_aes_key)
            print("Using AES key from SecureFile (owner)")
        else:
            # Use the re-encrypted AES key from FileShare
            file_share = FileShare.objects.get(file=secure_file, shared_with=request.user)
            encrypted_aes_key = bytes.fromhex(file_share.encrypted_aes_key)
            print("Using AES key from FileShare (shared)")
            print(f"FileShare encrypted AES key length: {len(file_share.encrypted_aes_key)}")
        
        print(f"Encrypted AES key bytes length: {len(encrypted_aes_key)}")
        
        # Decrypt AES key
        try:
            aes_key = decrypt_rsa(encrypted_aes_key, user_profile.rsa_private_key)
            print(f"AES key decrypted successfully, length: {len(aes_key)} bytes")
        except Exception as e:
            print(f"ERROR decrypting AES key: {e}")
            raise
        
        # Decrypt file
        try:
            decrypted_data = decrypt_file_aes(encrypted_data, aes_key)
            print(f"File decrypted successfully, size: {len(decrypted_data)} bytes")
        except Exception as e:
            print(f"ERROR decrypting file with AES: {e}")
            raise
        
        # Create response
        response = HttpResponse(decrypted_data, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{secure_file.original_filename}"'
        
        # Log successful download
        SecurityLog.objects.create(
            user=request.user,
            action='FILE_DOWNLOAD',
            description=f'Downloaded file: {secure_file.original_filename}',
            ip_address=get_client_ip(request)
        )
        
        print("=== DEBUG DOWNLOAD END (SUCCESS) ===\n")
        return response
    
    except Exception as e:
        print(f"\n=== DEBUG DOWNLOAD ERROR ===")
        print(f"Error type: {type(e).__name__}")
        print(f"Error message: {str(e)}")
        import traceback
        traceback.print_exc()
        print("=== DEBUG DOWNLOAD END (ERROR) ===\n")
        
        from logs.models import SecurityLog
        SecurityLog.objects.create(
            user=request.user,
            action='FILE_DECRYPTION_ERROR',
            description=f'Decryption failed for {secure_file.original_filename}: {str(e)}',
            ip_address=get_client_ip(request)
        )
        
        messages.error(request, f'Error decrypting file: {str(e)}')
        return redirect('file_list')

# ADD THIS MISSING FUNCTION
@login_required
def file_share_view(request, file_id):
    secure_file = get_object_or_404(SecureFile, id=file_id, owner=request.user)
    
    if request.method == 'POST':
        from accounts.models import UserProfile, CustomUser
        from logs.models import SecurityLog
        
        shared_with_id = request.POST.get('shared_with')
        permission = request.POST.get('permission')
        
        try:
            print(f"\n=== DEBUG SHARING START ===")
            print(f"File: {secure_file.original_filename}")
            print(f"Owner: {request.user.username}")
            print(f"Sharing with user ID: {shared_with_id}")
            
            shared_user = CustomUser.objects.get(id=shared_with_id)
            print(f"Shared user: {shared_user.username}")
            
            # Get owner's RSA keys
            owner_profile = UserProfile.objects.get(user=request.user)
            print(f"Owner RSA public key length: {len(owner_profile.rsa_public_key)}")
            
            # Get shared user's RSA public key
            shared_user_profile = UserProfile.objects.get(user=shared_user)
            print(f"Shared user RSA public key length: {len(shared_user_profile.rsa_public_key)}")
            
            # Get original AES key (decrypt with owner's private key)
            encrypted_aes_key = bytes.fromhex(secure_file.encrypted_aes_key)
            print(f"Original encrypted AES key length: {len(encrypted_aes_key)} bytes")
            
            try:
                original_aes_key = decrypt_rsa(encrypted_aes_key, owner_profile.rsa_private_key)
                print(f"Original AES key retrieved, length: {len(original_aes_key)} bytes")
            except Exception as e:
                print(f"ERROR: Could not decrypt original AES key: {e}")
                raise
            
            # Re-encrypt AES key with shared user's public key
            re_encrypted_aes_key = encrypt_rsa(original_aes_key, shared_user_profile.rsa_public_key)
            print(f"Re-encrypted AES key length: {len(re_encrypted_aes_key)} bytes")
            
            # Create or update file share
            file_share, created = FileShare.objects.update_or_create(
                file=secure_file,
                shared_with=shared_user,
                defaults={
                    'permission': permission,
                    'encrypted_aes_key': re_encrypted_aes_key.hex()
                }
            )
            
            print(f"File share {'created' if created else 'updated'}")
            print(f"Stored encrypted AES key in share: {file_share.encrypted_aes_key[:64]}...")
            
            # Test if shared user can decrypt it
            try:
                test_decrypted = decrypt_rsa(re_encrypted_aes_key, shared_user_profile.rsa_private_key)
                print(f"Test: Shared user can decrypt AES key: {test_decrypted == original_aes_key}")
            except Exception as e:
                print(f"WARNING: Shared user cannot decrypt AES key: {e}")
            
            # Log sharing activity
            SecurityLog.objects.create(
                user=request.user,
                action='FILE_SHARED',
                description=f'Shared file {secure_file.original_filename} with {shared_user.username}',
                ip_address=get_client_ip(request)
            )
            
            print("=== DEBUG SHARING END (SUCCESS) ===\n")
            messages.success(request, f'File shared successfully with {shared_user.username}')
            return redirect('file_list')
        
        except Exception as e:
            print(f"\n=== DEBUG SHARING ERROR ===")
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
            print("=== DEBUG SHARING ERROR END ===\n")
            
            messages.error(request, f'Error sharing file: {str(e)}')
    
    return redirect('file_list')

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

@login_required
def file_view_view(request, file_id):
    """View file content in browser"""
    secure_file = get_object_or_404(SecureFile, id=file_id)
    
    # Check permissions
    if secure_file.owner != request.user and not FileShare.objects.filter(file=secure_file, shared_with=request.user).exists():
        messages.error(request, 'You do not have permission to view this file.')
        return redirect('file_list')
    
    try:
        from accounts.models import UserProfile
        from logs.models import SecurityLog
        
        # Read encrypted file
        with open(secure_file.encrypted_file.path, 'rb') as f:
            encrypted_data = f.read()
        
        # Verify file integrity
        current_hash = compute_file_hash(encrypted_data)
        if current_hash != secure_file.file_hash:
            messages.error(request, 'File integrity check failed. File may have been tampered with.')
            return redirect('file_list')
        
        # Get user's RSA private key
        user_profile = UserProfile.objects.get(user=request.user)
        
        # Decrypt AES key
        encrypted_aes_key = bytes.fromhex(secure_file.encrypted_aes_key)
        aes_key = decrypt_rsa(encrypted_aes_key, user_profile.rsa_private_key)
        
        # Decrypt file
        decrypted_data = decrypt_file_aes(encrypted_data, aes_key)
        
        # Determine content type
        import mimetypes
        content_type, _ = mimetypes.guess_type(secure_file.original_filename)
        if not content_type:
            content_type = 'application/octet-stream'
        
        # For text files, show in browser
        if content_type.startswith('text/') or content_type in ['application/json', 'application/xml']:
            try:
                content = decrypted_data.decode('utf-8')
            except:
                content = decrypted_data.decode('latin-1')
            
            context = {
                'filename': secure_file.original_filename,
                'content': content,
                'content_type': content_type,
                'file_size': len(decrypted_data),
                'file': secure_file,
                'file_id': file_id,  
            }
            
            # Log view action
            SecurityLog.objects.create(
                user=request.user,
                action='FILE_VIEW',
                description=f'Viewed file: {secure_file.original_filename}',
                ip_address=get_client_ip(request)
            )
            
            return render(request, 'files/file_view.html', context)
        else:
            # For binary files, offer download
            messages.info(request, 'This file type cannot be displayed in browser. Please download it.')
            return redirect('file_download', file_id=file_id)
    
    except Exception as e:
        messages.error(request, f'Error viewing file: {str(e)}')
        return redirect('file_list')

@login_required
def file_delete_view(request, file_id):
    """Delete a file"""
    secure_file = get_object_or_404(SecureFile, id=file_id, owner=request.user)
    
    try:
        filename = secure_file.original_filename
        
        # Delete the physical file
        if os.path.exists(secure_file.encrypted_file.path):
            os.remove(secure_file.encrypted_file.path)
        
        # Delete the database record
        secure_file.delete()
        
        # Log the deletion
        from logs.models import SecurityLog
        SecurityLog.objects.create(
            user=request.user,
            action='FILE_DELETE',
            description=f'Deleted file: {filename}',
            ip_address=get_client_ip(request)
        )
        
        messages.success(request, f'File "{filename}" deleted successfully.')
    
    except Exception as e:
        messages.error(request, f'Error deleting file: {str(e)}')
    
    return redirect('file_list')
@login_required
def remove_shared_file_view(request, file_id):
    """Remove a shared file from user's shared files list"""
    secure_file = get_object_or_404(SecureFile, id=file_id)
    
    # Check if file is shared with user
    try:
        file_share = FileShare.objects.get(file=secure_file, shared_with=request.user)
        filename = secure_file.original_filename
        owner = secure_file.owner.username
        
        # Delete the file share (this removes it from user's shared list)
        file_share.delete()
        
        # Log the action
        from logs.models import SecurityLog
        SecurityLog.objects.create(
            user=request.user,
            action='SHARED_FILE_REMOVED',
            description=f'Removed shared file "{filename}" (owner: {owner}) from shared list',
            ip_address=get_client_ip(request)
        )
        
        messages.success(request, f'File "{filename}" has been removed from your shared files.')
        
    except FileShare.DoesNotExist:
        messages.error(request, 'This file is not shared with you or you do not have permission to remove it.')
    
    return redirect('file_list')