from .serializers import CustomUserSerializer
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from rest_framework.decorators import api_view, authentication_classes, permission_classes
import qrcode
import io
from django.http import HttpResponse
from .permissions import IsOTPVerified
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import login
from django.contrib.auth import get_user_model
from rest_framework.permissions import AllowAny
from rest_framework.authtoken.models import Token
import pyotp
import logging


class SignupView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.totp_secret = pyotp.random_base32()
            user.save()
            return Response({'message': 'User created successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


User = get_user_model()


User = get_user_model()
logger = logging.getLogger(__name__)

class LoginAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            email = request.data.get('email')
            password = request.data.get('password')

            user = User.objects.filter(email=email).first()

            if user and user.check_password(password):
                login(request, user)
                user.otp_verified = False
                user.save()

                token, _ = Token.objects.get_or_create(user=user)
                totp = pyotp.TOTP(user.totp_secret)
                current_otp = totp.now()

                return Response({
                    'token': token.key,
                    'otp_for_testing': current_otp,
                    'first_name': user.first_name,
                    'last_name': user.last_name
                })

            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            return Response({'error': 'Internal server error'}, status=500)

@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated, IsOTPVerified])
def protected_view(request):
    user = request.user
    if not user.otp_verified:
        return Response({"error": "OTP not verified"}, status=status.HTTP_403_FORBIDDEN)

    return Response({
        'email': request.user.email,
        'first_name': request.user.first_name,
        'last_name': request.user.last_name
    })


@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def logout_view(request):
    request.user.auth_token.delete()
    request.user.otp_verified = False  # Reset OTP status on logout
    request.user.save()
    return Response({'message': 'Logged out successfully'}, status=status.HTTP_200_OK)



@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def generate_qr(request):
    user = request.user

    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        user.save()

    totp = pyotp.TOTP(user.totp_secret)
    uri = totp.provisioning_uri(name=user.email, issuer_name="QROTP Project")

    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf, format='PNG')
    buf.seek(0)


    from django.core.files.base import ContentFile
    file_name = f"qr_codes/{user.email.replace('@', '_at_')}_qr.png"
    user.qr_code_image.save(file_name, ContentFile(buf.read()), save=True)

    qr_code_url = request.build_absolute_uri(user.qr_code_image.url)
    return Response({'qr_code_url': qr_code_url})



@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def verify_otp(request):
    otp = request.data.get('otp')
    user = request.user
    print("📌 Authenticated user:", user, "| Email:", user.email if hasattr(user, 'email') else 'N/A')

    if not user.totp_secret:
        return Response({'error': 'TOTP secret not set for user'}, status=status.HTTP_400_BAD_REQUEST)

    totp = pyotp.TOTP(user.totp_secret)
    if totp.verify(otp):
        user.otp_verified = True
        user.save()
        return Response({'message': 'OTP verified successfully'}, status=status.HTTP_200_OK)
    else:
        return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def reset_totp(request):
    user = request.user

    # Reset the TOTP secret
    user.totp_secret = pyotp.random_base32()
    user.otp_verified = False  # Require re-verification
    user.save()

    # Generate new QR code
    totp = pyotp.TOTP(user.totp_secret)
    uri = totp.provisioning_uri(name=user.email, issuer_name="QROTP Project")
    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf)
    buf.seek(0)

    return HttpResponse(buf.getvalue(), content_type='image/png')

@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def get_totp_secret(request):
    user = request.user

    # Generate and save a new TOTP secret if not already present
    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        user.save()

    return Response({'totp_secret': user.totp_secret})
