from rest_framework.views import APIView
from rest_framework import status
from .serializers import CustomUserSerializer
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
import pyotp
import qrcode
import io
from django.http import HttpResponse
from .permissions import IsOTPVerified
from rest_framework import status


class SignupView(APIView):
    def post(self, request):
        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'User created successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



User = get_user_model()

class LoginAPIView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        user = User.objects.filter(email=email).first()
        if user and user.check_password(password):
            user.otp_verified = False
            user.save()

            token, created = Token.objects.get_or_create(user=user)
            totp = pyotp.TOTP(user.totp_secret)
            current_otp = totp.now()

            return Response({
                'token': token.key,
                'first_name': user.first_name or "",
                'last_name': user.last_name or "",
                'otp_for_testing': current_otp
            })
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)




@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated, IsOTPVerified])
def protected_view(request):
    user = request.user
    if not user.otp_verified:
        return Response({"error": "OTP not verified"}, status=status.HTTP_403_FORBIDDEN)

    return Response({"message": f"Hello, {user.email}! You are authenticated."})



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

    # Generate and save TOTP secret if not already there
    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        user.save()

    # Generate provisioning URI
    totp = pyotp.TOTP(user.totp_secret)
    uri = totp.provisioning_uri(name=user.email, issuer_name="QROTP Project")

    # Generate QR code image
    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf)
    buf.seek(0)

    return HttpResponse(buf.getvalue(), content_type='image/png')

@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def verify_otp(request):
    otp = request.data.get('otp')
    user = request.user

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
