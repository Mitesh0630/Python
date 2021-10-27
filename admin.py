from django.contrib import admin
from .models import Otp, User, Profile
from .forms import NewUserForm
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.utils.translation import ugettext_lazy as _

# Register your models here.


@admin.register(User)
class UserAdmin(DjangoUserAdmin, NewUserForm):
    list_display = ['id', 'email', 'first_name', 'contact', 'is_active', 'is_admin', 'is_superuser', ]

    readonly_fields = ('date_joined',)

    # add form of the model
    add_form = NewUserForm

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name')}),
        (_('Permissions'), {'fields': ('is_active', 'is_admin', 'is_superuser',
                                       'groups', 'user_permissions')}),
        (_('Important dates'), {'fields': ('last_login','date_joined',)}),
    )

    add_fieldsets = (
        (None, {'fields': ('email','password1', 'password2',)}),
        (_('Personal info'), {'fields': ('first_name', 'last_name', 'contact')}),
        (_('Permissions'), {'fields': ('is_active', 'is_admin', 'is_superuser',
                                       'groups', 'user_permissions')}),
        # (None, {
        #     'classes': ('wide',),
        #     'fields': ('first_name', 'last_name', 'email', 'contact', 'password1', 'password2', 'is_admin', 'is_active', 'is_superuser',),
        # }),
    )

    list_display_links = ('id', 'email')

    search_fields = ('email', 'first_name', 'last_name')

    ordering = ('id',)

    list_filter = ('is_active', 'is_admin', 'is_superuser')


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'is_convoy', 'min_distance', 'max_distance']

    list_filter = ('is_convoy',)

@admin.register(Otp)
class OtpAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'otp',]
