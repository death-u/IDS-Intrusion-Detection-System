from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login, logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.utils import timezone
from datetime import timedelta
from .models import LoginAttempt, IntrusionLog, IDSSettings
from django.contrib.auth.decorators import login_required

BRUTE_FORCE_THRESHOLD = 5      # max failed attempts
BRUTE_FORCE_WINDOW_MINUTES = 10  # time window to count attempts in


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')


def is_brute_force(ip):
    window_start = timezone.now() - timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)
    recent_failures = LoginAttempt.objects.filter(
        ip_address=ip,
        success=False,
        timestamp__gte=window_start
    ).count()
    return recent_failures >= BRUTE_FORCE_THRESHOLD


def login_view(request):
    if request.user.is_authenticated:
        return redirect('about')

    if request.method == 'POST':
        ip = get_client_ip(request)

        # Check brute-force BEFORE processing the attempt
        if is_brute_force(ip):
            IntrusionLog.objects.create(
                ip_address=ip,
                attack_type='brute_force',
                path=request.path,
                payload=f"Repeated failed login attempts from {ip}",
                blocked=True,
            )
            messages.error(request, "Too many failed attempts. Try again later.")
            return render(request, 'login.html')

        email = request.POST.get("email")
        password = request.POST.get("password")

        if not email or not password:
            LoginAttempt.objects.create(ip_address=ip, email_attempted=email or '', success=False)
            messages.error(request, "Invalid email or password.")
            return render(request, 'login.html')

        user = None
        try:
            user_obj = User.objects.get(email=email)
            user = authenticate(request, username=user_obj.username, password=password)
        except User.DoesNotExist:
            pass

        if user is not None:
            LoginAttempt.objects.create(ip_address=ip, email_attempted=email, success=True)
            auth_login(request, user)
            messages.success(request, "Logged in successfully.")
            return redirect('about')
        else:
            LoginAttempt.objects.create(ip_address=ip, email_attempted=email, success=False)
            messages.error(request, "Invalid email or password.")

    return render(request, 'login.html')


def register(request):
    if request.user.is_authenticated:
        return redirect('about')

    if request.method == 'POST':
        username = request.POST.get("username")
        email = request.POST.get("email")
        password1 = request.POST.get("password1")
        password2 = request.POST.get("password2")

        if not username or not email or not password1 or not password2:
            messages.error(request, "All fields are required.")
            return render(request, 'register.html')

        if password1 != password2:
            messages.error(request, "Passwords do not match.")
            return render(request, 'register.html')

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already taken.")
            return render(request, 'register.html')

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already registered.")
            return render(request, 'register.html')

        User.objects.create_user(username=username, email=email, password=password1)
        messages.success(request, "Account created successfully. Please log in.")
        return redirect('login')

    return render(request, 'register.html')


def about(request):
    return render(request, 'about.html')


def logout_view(request):
    logout(request)
    messages.success(request, "You've been logged out successfully.")
    return redirect('login')



@login_required
def dashboard(request):
    ids_settings = IDSSettings.get_settings()
    logs = IntrusionLog.objects.all()[:100]
    total_attacks = IntrusionLog.objects.count()
    sqli_count = IntrusionLog.objects.filter(attack_type='sqli').count()
    xss_count = IntrusionLog.objects.filter(attack_type='xss').count()
    brute_force_count = IntrusionLog.objects.filter(attack_type='brute_force').count()
    path_traversal_count = IntrusionLog.objects.filter(attack_type='path_traversal').count()

    context = {
        'logs': logs,
        'total_attacks': total_attacks,
        'sqli_count': sqli_count,
        'xss_count': xss_count,
        'brute_force_count': brute_force_count,
        'path_traversal_count': path_traversal_count,
        'ids_active': ids_settings.is_active,
    }
    return render(request, 'dashboard.html', context)


@login_required
def toggle_ids(request):
    settings_obj = IDSSettings.get_settings()
    settings_obj.is_active = not settings_obj.is_active
    settings_obj.save()
    status = "enabled" if settings_obj.is_active else "disabled"
    messages.success(request, f"IDS has been {status}.")
    return redirect('dashboard')