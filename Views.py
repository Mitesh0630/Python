from django.http.response import HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect, render
from django.contrib.auth import login,authenticate,logout
from django.utils.translation import gettext_lazy as _gtl
from django.contrib import messages
from .forms import (
    NewUserForm,
    OtpForm, 
    UserLoginForm, 
    CustomPasswordChangeForm, 
    UserSetPasswordForm, 
    PasswordResetForm,
    UserUpdateForm,
    ProfileForm
)
from django.contrib.auth import authenticate
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.views import LoginView as DjangoLoginView
from django.views.generic import CreateView, UpdateView
from django.urls import reverse_lazy as _
from django.contrib.auth.decorators import login_required
from .models import User, Profile
from django.contrib.auth.views import (
    PasswordChangeView, 
    PasswordResetView as DjangoPasswordResetView, 
    PasswordResetConfirmView as DjangoPasswordResetConfirmView
)
from django.utils.decorators import method_decorator
from django.utils import timezone
from django.utils.timezone import datetime
from dateutil.relativedelta import relativedelta
from datetime import datetime as dt
from django.conf import settings

from django.core.mail import send_mail
from .tokens import account_activation_token
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_text, force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
# Create your views here.



def signup_request(request):
    if request.user.is_authenticated:
        return redirect(_('index'))
    if request.method == "POST":
        form = NewUserForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, "Signup successful." )
            return redirect("login")
        messages.error(request, "Unsuccessful registration. Invalid information.")
    form = NewUserForm()
    return render(request,'signup.html', context={"form":form})


class RegisterView(CreateView):
    '''User Create View
        This view is rendered when signup/ page is called. 
        After the successful registration it redirects the user to login page.
        User Created from this view are by default "Builders" and are allowed to login
    '''
    form_class = NewUserForm
    template_name = 'signup.html'
    success_url = _('login')

    def get(self, request):
        if request.user.is_authenticated:
            storage = messages.get_messages(request)
            storage.used = True
            return redirect(_('login'))
        return super().get(self, request)

    def post(self, request, *args, **kwargs):
        try:
            u = User.objects.get(email = request.POST.get('email'))
            if u.is_active == False:
                u.delete()
        except:
            pass
        response = super().post(request, *args, **kwargs)
        user_email = request.POST.get('email')

        if response.status_code == 302:
            user = User.objects.get(email = user_email)
            user.is_active = False
            user.save()

            current_site = get_current_site(request)
            mail_subject = 'Activate Your account.'
            message = render_to_string('emails/acc_active_email.html',{
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': account_activation_token.make_token(user),
            })
            to_email = user_email
            form = self.get_form()
            try:
                send_mail(
                    subject= mail_subject,
                    message= message,
                    from_email= settings.EMAIL_HOST_USER,
                    recipient_list= [to_email],
                    fail_silently= False,
                    html_message = message,
                )
                messages.success(request, 'A confirmation email has been sent to your email account. Please click on the link to confirm your account.')
                return self.render_to_response({'form':form})
            except Exception as e:
                messages.error(request, f'Error occured in sending mail! Please try again. {e}')
                return self.render_to_response({'form':form})
        else:
            return response
    
def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist) as e:
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()

        login(request, user)
        messages.success(request, 'Successfully Logged in!')
        return redirect(_('index'))
    else:
        return HttpResponse('Activation token is invalid or your account is already verified! Try to login.')



def login_view(request):
    if request.user.is_authenticated:
        return redirect(_('index'))
    context = {}
    form = UserLoginForm()
    context['form'] = form
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            code = user.otp
            code = code.save()
            request.session['pk'] = user.pk
            request.session['otp_send'] = True
            messages.success(request, 'We have sent you an OTP on your registered email. Enter that OTP to login.')
            return redirect('verify-login')
        else:
            messages.error(request, 'Please Enter a valid Email and password.')
    return render(request, 'login.html', context)

def verify_view(request):
    if request.user.is_authenticated and request.session.get('pk'):
        return redirect(_('index'))
    context = {}
    form = OtpForm(request.POST or None)
    context['form'] = form
    pk = request.session.get('pk')
    otp_send = request.session.get('otp_send', False)
    if pk:
        user = User.objects.get(pk=pk)
        code = user.otp
        print('otp',code)

        if otp_send and not request.POST:
            # send OTP
            email_template = 'emails/send_otp.html'
            subject = 'Your OTP for login!'
            message = f'{code}'
            e = user.email_user(subject, message, email_template)
            print(e)
            del request.session['otp_send']

        if request.method == 'POST' and form.is_valid():
            otp = form.cleaned_data.get('otp')

            if str(code) == otp:
                print(relativedelta(code.timestamp, timezone.now()).minutes)
                if abs(relativedelta(code.timestamp, timezone.now()).minutes) < 3:
                    login(request, user)
                    try:
                        del request.session['pk']
                    except Exception:
                        print('no session named pk')
                    return redirect('index')
                else:
                    messages.error(request, 'OTP has expired please generate a new one to login.')
                    return HttpResponseRedirect(request.META.get('HTTP_REFERER'))
            else:
                messages.error(request, 'OTP is not correct.')
                return HttpResponseRedirect(request.META.get('HTTP_REFERER'))
    return render(request, 'user/verify.html', context)


def send_otp_again(request):
    if request.user.is_authenticated and request.session.get('pk'):
        return redirect(_('index'))
    try:
        pk = request.session.get('pk')
        user = User.objects.get(pk=pk)
        code = user.otp
        code = code.save()
        code = user.otp
        print('send-otp-again: ',code)
    except Exception as e:
        print('login to receive otp', e)
    # send OTP
    email_template = 'emails/send_otp.html'
    subject = 'Your OTP for login!'
    message = f'{code}'
    e = user.email_user(subject, message, email_template)
    print(e)
    messages.success(request, 'A new OTP has been sent to your registered E-mail.')
    return redirect('verify-login')

class LoginView(DjangoLoginView):
    '''User Login View
    '''
    form_class = UserLoginForm
    model = User
    template_name = 'login.html'
    success_url = _('index')

    def get(self, request, *args, **kwargs):
        context = {'form':self.form_class}
        if request.user.is_authenticated:
            return redirect(_('index'))
        return render(request,"login.html", context)
    

@login_required()
def index(request):
    return render(request,'index.html')

def logout_request(request):
	logout(request)
	messages.info(request, "You have successfully logged out.") 
	return redirect(request,'login.html')


class UserPasswordChangeView(PasswordChangeView):
    '''UserPasswordChabngeView
    this view is used to render change password form.'''
    template_name = 'user/password-change.html'
    form_class = CustomPasswordChangeForm
    success_url = _('password-change-done')


class UserPasswordResetView(DjangoPasswordResetView):
    '''UserPasswordResetView
    This view is used as forgot password system.
    it renders PasswordResetForm which has 1 field email that will be used to send a reset password email.
    '''
    form_class = PasswordResetForm

class UserPasswordResetConfirmView(DjangoPasswordResetConfirmView):
    '''UserPasswordResetView
    This view is used as forgot password system.
    it renders UserSetPasswordForm which has 2 field 'new password' and 'confirm password' that will be used to set a new password.
    this view will be accesible by the link sent to the email by the UserPasswordResetView().
    '''
    form_class = UserSetPasswordForm


class UserUpdateView(UpdateView):
    model = User
    form_class = UserUpdateForm
    template_name = 'user/user-update.html'
    success_url = _('account-settings')

    def get_object(self, queryset=None):
        return self.request.user

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        profile = Profile.objects.get(user=self.request.user)
        context['profile_form'] = ProfileForm(instance=profile)
        return context

    @method_decorator([login_required,])
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        form = self.get_form()
        if form.is_valid():
            messages.success(request, "Account info saved!")
            return self.form_valid(form)
        else:
            for item in form.errors.items():
                messages.error(request, item[1], extra_tags=f'danger {item[0]}')
            return self.form_invalid(form)


class ProfileUpdateView(UpdateView):
    model = Profile
    form_class = ProfileForm
    template_name = 'user/profile-update.html'
    success_url = _('account-settings')

    def get_object(self, queryset=None):
        return self.request.user.profile

    @method_decorator([login_required,])
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        form = self.get_form()
        if form.is_valid():
            form.save()
            messages.success(request, "Profile info saved!")
            return redirect(_('account-settings'))
        else:
            for item in form.errors.items():
                messages.error(request, item[1], extra_tags=f'danger {item[0]}')
            # return self.form_invalid(form)
            return redirect(_('account-settings'))
