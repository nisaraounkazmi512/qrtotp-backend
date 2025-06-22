from django.urls import path
from .views import SignupView, LoginAPIView, protected_view, logout_view, generate_qr
from .views import verify_otp, reset_totp
from django.conf import settings
from django.conf.urls.static import static
from django.urls import path, include
from django.contrib import admin
from django.urls import path, include


urlpatterns = [
    path('signup/', SignupView.as_view(), name='signup'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('protected/', protected_view, name='protected'),
    path('logout/', logout_view, name='logout'),
    path('generate-qr/', generate_qr, name='generate_qr'),
    path('verify-otp/', verify_otp, name='verify_otp'),
    path('reset-totp/', reset_totp, name='reset_totp'),
    path('api/', include('accounts.urls')),
    path('admin/', admin.site.urls),
    path('api/', include('accounts.urls')),

]
