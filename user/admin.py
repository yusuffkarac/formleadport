from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, SifreSifirlamaTalebi
# Register your models here.

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    list_display = ("username", "email", "first_name", "last_name", "rol", "last_login", "date_joined")
    search_fields = ("username", "email", "first_name", "last_name")
    list_filter = ("is_staff", "is_superuser", "is_active", "groups")
    fieldsets = (
        ("Kullanıcı Bilgileri", {"fields": ("username", "password")}),
        ("Kişisel Bilgiler", {"fields": ("first_name", "last_name", "email", "rol", "aktif", "resim", "silinme_tarihi")}),
        ("İzinler", {"fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions")}),
        ("Önemli Tarihler", {"fields": ("last_login", "date_joined")}),
    )
    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("username", "email", "password1", "password2", "is_active", "is_staff"),
        }),
    )
    ordering = ("-date_joined",)
    readonly_fields = ("last_login", "date_joined")

    class Meta:
        model = CustomUser


@admin.register(SifreSifirlamaTalebi)
class SifreSifirlamaTalebiAdmin(admin.ModelAdmin):
    list_display = ('user', 'created_at', 'used_at')
    search_fields = ('user__username',)
    list_filter = ('used_at', 'created_at')