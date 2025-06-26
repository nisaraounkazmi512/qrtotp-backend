from django.urls import path
from .views import SignupView, LoginAPIView, protected_view, logout_view, generate_qr
from .views import verify_otp, reset_totp
from .views import get_totp_secret


urlpatterns = [
    path('signup/', SignupView.as_view(), name='signup'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('protected/', protected_view, name='protected'),
    path('logout/', logout_view, name='logout'),
    path('generate-qr/', generate_qr, name='generate_qr'),
    path('verify-otp/', verify_otp, name='verify_otp'),
    path('reset-totp/', reset_totp, name='reset_totp'),
    path('get-totp-secret/', get_totp_secret, name='get-totp-secret'),
]
