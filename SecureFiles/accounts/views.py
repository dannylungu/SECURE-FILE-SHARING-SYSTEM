from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .forms import CustomUserCreationForm, LoginForm
from .models import UserProfile, CustomUser
from files.crypto_utils import generate_rsa_key_pair
from logs.models import SecurityLog

def get_client_ip(request):
    """Helper function to get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def register_view(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            
            # Generate RSA key pair for the user
            try:
                private_key, public_key = generate_rsa_key_pair()
                print(f"Generated RSA keys for user {user.username}")
                print(f"Private key (first 100 chars): {private_key[:100]}...")
                print(f"Public key (first 100 chars): {public_key[:100]}...")
                
                # Create user profile with RSA keys
                user_profile, created = UserProfile.objects.get_or_create(
                    user=user,
                    defaults={
                        'rsa_public_key': public_key,
                        'rsa_private_key': private_key
                    }
                )
                
                if not created:
                    # Update existing profile
                    user_profile.rsa_public_key = public_key
                    user_profile.rsa_private_key = private_key
                    user_profile.save()
                
                # Update user model with keys
                user.public_key = public_key
                user.private_key = private_key
                user.save()
                
                print(f"UserProfile created/updated for {user.username}")
                
                # Test the keys work
                from files.crypto_utils import encrypt_rsa, decrypt_rsa, generate_aes_key
                test_data = b"Test message"
                encrypted = encrypt_rsa(test_data, public_key)
                decrypted = decrypt_rsa(encrypted, private_key)
                print(f"Key test passed: {test_data == decrypted}")
                
            except Exception as e:
                print(f"Error creating UserProfile for {user.username}: {e}")
                import traceback
                traceback.print_exc()
                messages.error(request, f'Error creating user profile: {e}')
                return redirect('register')
            
            # Log the registration
            SecurityLog.objects.create(
                user=user,
                action='REGISTRATION',
                description=f'User {user.username} registered successfully',
                ip_address=get_client_ip(request)
            )
            
            messages.success(request, 'Registration successful! Please log in.')
            return redirect('login')
    else:
        form = CustomUserCreationForm()
    
    return render(request, 'accounts/register.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            
            if user is not None:
                login(request, user)
                
                # Log successful login
                SecurityLog.objects.create(
                    user=user,
                    action='LOGIN_SUCCESS',
                    description=f'User {username} logged in successfully',
                    ip_address=get_client_ip(request)
                )
                
                messages.success(request, f'Welcome back, {username}!')
                return redirect('dashboard')
            else:
                # Log failed login attempt
                SecurityLog.objects.create(
                    user=None,
                    action='LOGIN_FAILED',
                    description=f'Failed login attempt for username: {username}',
                    ip_address=get_client_ip(request)
                )
                
                messages.error(request, 'Invalid username or password.')
    else:
        form = LoginForm()
    
    return render(request, 'accounts/login.html', {'form': form})

def logout_view(request):
    if request.user.is_authenticated:
        # Log logout
        SecurityLog.objects.create(
            user=request.user,
            action='LOGOUT',
            description=f'User {request.user.username} logged out',
            ip_address=get_client_ip(request)
        )
    
    logout(request)
    messages.info(request, 'You have been logged out.')
    return redirect('login')

@login_required
def dashboard_view(request):
    # Check if user has a profile
    try:
        user_profile = UserProfile.objects.get(user=request.user)
        has_profile = True
    except UserProfile.DoesNotExist:
        has_profile = False
        messages.warning(request, 'Your user profile is not set up properly. Please contact administrator.')
    
    # Import here to avoid circular import
    from files.models import SecureFile
    
    user_files = SecureFile.objects.filter(owner=request.user)
    shared_files = SecureFile.objects.filter(shares__shared_with=request.user)
    
    context = {
        'user_files': user_files,
        'shared_files': shared_files,
        'has_profile': has_profile,
    }
    return render(request, 'accounts/dashboard.html', context)