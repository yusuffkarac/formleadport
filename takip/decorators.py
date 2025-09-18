from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages

def rol_kontrol(allowed_roles=("Admin", "Yönetici"), redirect_url="panel"):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('giris')
            if getattr(request.user, "rol", None) not in allowed_roles:
                messages.error(request, "Sie haben keine Berechtigung, um diese Seite anzuzeigen.")
                return redirect(redirect_url)

            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator
