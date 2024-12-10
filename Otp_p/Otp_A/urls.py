from django.urls import path
from .views import RegistrationView, ValidateOTPView, LoginView,ForgotPasswordView, VerifyOTPView, ResetPasswordView

urlpatterns = [
    path('register/', RegistrationView.as_view(), name='register'),
    path('validate-otp-register/', ValidateOTPView.as_view(), name='validate-otp'),
    path('login/', LoginView.as_view(), name='login'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    # path('verify-otp-res-pass/', VerifyOTPView.as_view(), name='verify-otp'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),
]
