from django import forms
from django.forms.widgets import PasswordInput
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.forms import UserCreationForm
from .models import Otp, User, Profile
from django.core.exceptions import ValidationError
from django.contrib.auth import password_validation
from django.contrib.auth.forms import AuthenticationForm, UsernameField, PasswordChangeForm, PasswordResetForm as DjangoPasswordResetForm, SetPasswordForm
from django.forms import PasswordInput, EmailInput




# Create your forms here.

class NewUserForm(UserCreationForm):

    error_messages = {
        'password_mismatch': _('The two password fields didn’t match.'),
        'invalid_first_name': _('First Name should only conatin Alphabets.'),
        'invalid_last_name': _('Last Name should only conatin Alphabets.'),
        'invalid_email': _('Email is not a valid email address.'),
        'invalid_contact': _('Contact Number is not a valid Contact Number.'),
    }
    contact = forms.CharField( label='Contact', 
        widget=forms.TextInput(attrs={'placeholder':'Contact', 'class': 'form-control',}))

    password1 = forms.CharField(
        label='Password', 
        widget=forms.PasswordInput(attrs={'placeholder':'Password', 'class': 'form-control',}),
        help_text=password_validation.password_validators_help_text_html(),
    )
    password2 = forms.CharField(
        label='Password confirmation', 
        widget=forms.PasswordInput(attrs={'placeholder':'Confirm Password', 'class': 'form-control',}),
        help_text=_("Enter the same password as before, for verification."),
    )

    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email', 'contact','password1', 'password2')
        widgets = {
            'first_name': forms.TextInput(attrs={'placeholder':'First Name', 'class': 'form-control','required':'true',}),
            'last_name': forms.TextInput(attrs={'placeholder':'Last Name', 'class': 'form-control','required':'true',}),
            'email': forms.EmailInput(attrs={'placeholder':'Email', 'class': 'form-control','required':'true',}),
            'contact': forms.TextInput(attrs={'placeholder':'Contact', 'class': 'form-control','required':'true',}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self._meta.model.USERNAME_FIELD in self.fields:
            self.fields[self._meta.model.USERNAME_FIELD].widget.attrs['autofocus'] = True

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise ValidationError(
                self.error_messages['password_mismatch'],
                code='password_mismatch',
            )
        return password2

    def clean_first_name(self):
        first_name = self.cleaned_data.get("first_name")
        if first_name:
            if not first_name.isalpha():
                raise ValidationError(
                    self.error_messages['invalid_first_name'],
                    code='invalid_first_name',)
        else:
            raise ValidationError(
                self.error_messages['invalid_first_name'],
                code='invalid_first_name',)
        return first_name

    def clean_last_name(self):
        last_name = self.cleaned_data.get("last_name")
        if last_name:
            if not last_name.isalpha():
                raise ValidationError(
                    self.error_messages['invalid_last_name'],
                    code='invalid_last_name',)
        else:
            raise ValidationError(
                self.error_messages['invalid_last_name'],
                code='invalid_last_name',)
        return last_name

    def clean_contact(self):
        contact = self.cleaned_data.get("contact")
        import re
        pattern = re.compile("^[+]?[1-9][0-9]{9,14}$")
        if not pattern.match(contact):
            raise ValidationError(
                self.error_messages['invalid_contact'],
                code='invalid_contact',)

        return contact

    def clean_email(self):
        email = self.cleaned_data.get("email")
        import re
        pattern = re.compile("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$")
        if not pattern.match(email):
            raise ValidationError(
                self.error_messages['invalid_email'],
                code='invalid_email',)
        # if email and User.objects.filter(email=email).count():
        #         raise forms.ValidationError(_("This email address is already in use. Please supply a different email address."))
        return email



class UserLoginForm(AuthenticationForm):
    '''User Login Form
        Django form used as login form on login page.
        fields:
            username = username of the user
            password = valid password of the user
    '''
    username = UsernameField(
        widget=forms.TextInput(
            attrs={'autofocus': True, 'autocomplete': 'email', 'placeholder':'Email', 'class': 'form-control',}
        )
    )
    password = forms.CharField(
        label=_("Password"),
        strip=False,
        widget=forms.PasswordInput(attrs={'autocomplete': 'current-password', 'placeholder':'Password', 'class': 'form-control',}),
    )


class CustomPasswordChangeForm(PasswordChangeForm):
    old_password = forms.CharField(widget=PasswordInput(attrs={'placeholder':'Old Password','class': 'form-control'}))
    new_password1 = forms.CharField(widget=PasswordInput(attrs={'placeholder':'New Password','class': 'form-control'}))
    new_password2 = forms.CharField(widget=PasswordInput(attrs={'placeholder':'Confirm Password','class': 'form-control'}))
    
    class Meta:
        model = User


class PasswordResetForm(DjangoPasswordResetForm):
    '''forget password form'''
    email = forms.EmailField(widget=EmailInput(attrs={'placeholder':'Email','class': 'form-control'}))

    def clean_email(self):
        email = self.cleaned_data['email']
        if not User.objects.filter(email__iexact=email, is_active=True).exists():
            msg = _("There is no user registered with the specified E-Mail address.")
            self.add_error('email', msg)
        return email

class UserSetPasswordForm(SetPasswordForm):
    '''set new password form'''
    new_password1 = forms.CharField(
        label=_("New password"),
        widget=forms.PasswordInput(attrs={'placeholder':'New Password','class': 'form-control'}),
        strip=False,
        help_text=password_validation.password_validators_help_text_html(),
    )
    new_password2 = forms.CharField(
        label=_("New password confirmation"),
        strip=False,
        widget=forms.PasswordInput(attrs={'placeholder':'Confirm Password','class': 'form-control'}),
    )



class UserUpdateForm(forms.ModelForm):
    '''Update form for all users from settings menu after logging in .'''
    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email', 'contact')
        widgets = {
            'first_name': forms.TextInput(attrs={'placeholder':'First Name', 'class': 'form-control',}),
            'last_name': forms.TextInput(attrs={'placeholder':'Last Name', 'class': 'form-control',}),
            'email': forms.EmailInput(attrs={'placeholder':'Email', 'class': 'form-control', 'required':'true'}),
            'contact': forms.TextInput(attrs={'placeholder':'Contact Number', 'class': 'form-control', 'required':'true'}),
        }

    error_messages = {
        'invalid_first_name': _('First Name should only conatin Alphabets.'),
        'invalid_last_name': _('Last Name should only conatin Alphabets.'),
        'password_mismatch': _('The two password fields didn’t match.'),
        'invalid_email': _('Email is not valid.'),
        'invalid_contact': _('Contact Number is not valid.'),
    }

    def clean_first_name(self):
        first_name = self.cleaned_data.get("first_name")
        if first_name:
            if not first_name.isalpha():
                raise ValidationError(
                    self.error_messages['invalid_first_name'],
                    code='invalid_first_name',)
        else:
            raise ValidationError(
                self.error_messages['invalid_first_name'],
                code='invalid_first_name',)
        return first_name

    def clean_last_name(self):
        last_name = self.cleaned_data.get("last_name")
        if last_name:
            if not last_name.isalpha():
                raise ValidationError(
                    self.error_messages['invalid_last_name'],
                    code='invalid_last_name',)
        else:
            raise ValidationError(
                self.error_messages['invalid_last_name'],
                code='invalid_last_name',)
        return last_name

    def clean_contact(self):
        contact = self.cleaned_data.get("contact")
        import re
        pattern = re.compile("^[+]?[1-9][0-9]{9,14}$")
        if not pattern.match(contact):
            raise ValidationError(
                self.error_messages['invalid_contact'],
                code='invalid_contact',)

        return contact

    def clean_email(self):
        email = self.cleaned_data.get("email")
        import re
        pattern = re.compile("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$")
        if not pattern.match(email):
            raise ValidationError(
                self.error_messages['invalid_email'],
                code='invalid_email',)
        return email



class ProfileForm(forms.ModelForm):
    class Meta:
        model = Profile
        exclude = ('user',)
        widgets = {

            'pilot_uuid': forms.NumberInput(attrs={'placeholder':'Pilot UUID', 'class': 'form-control disable-spin-wheel',}),
            'truck_uuid': forms.NumberInput(attrs={'placeholder':'Truck UUID', 'class': 'form-control disable-spin-wheel',}),

            'is_convoy': forms.CheckboxInput(attrs={'class':'custom-control-input'}),
            'convoy_id': forms.NumberInput(attrs={'placeholder':'Convoy UUID', 'class': 'form-control disable-spin-wheel',}),

            'front_pilot_uuid': forms.NumberInput(attrs={'placeholder':'Front Pilot UUID', 'class': 'form-control disable-spin-wheel',}),
            'rear_pilot_uuid': forms.NumberInput(attrs={'placeholder':'Rear Pilot UUID', 'class': 'form-control disable-spin-wheel',}),
            'front_truck_uuid': forms.NumberInput(attrs={'placeholder':'Front Truck UUID', 'class': 'form-control disable-spin-wheel',}),
            'rear_truck_uuid': forms.NumberInput(attrs={'placeholder':'Rear Truck UUID', 'class': 'form-control disable-spin-wheel',}),

            'min_distance': forms.NumberInput(attrs={'placeholder':'Minimum Distance', 'class': 'form-control',}),
            'max_distance': forms.NumberInput(attrs={'placeholder':'Maximum Distance', 'class': 'form-control',}),

        }


class OtpForm(forms.ModelForm):
    class Meta:
        model = Otp
        fields = ('otp',)
        widgets = {
            'otp': forms.TextInput(attrs={'placeholder':'Enter OTP', 'class': 'form-control', 'required':'true',}),
        }
