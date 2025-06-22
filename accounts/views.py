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
import os
from django.conf import settings
import base64
from django.http import JsonResponse
from io import BytesIO
import qrcode


class SignupView(APIView):
    def post(self, request):
        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'User created successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class LoginAPIView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(username=username, password=password)
        if user is not None:
            user.otp_verified = False
            user.save()

            token, created = Token.objects.get_or_create(user=user)
            return Response({'token': token.key})
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
    import base64
    import pyotp
    import qrcode
    import io

    user = request.user

    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        user.save()

    totp = pyotp.TOTP(user.totp_secret)
    uri = totp.provisioning_uri(name=user.email, issuer_name="QROTP Project")

    # Generate QR code as image in memory
    qr = qrcode.make(uri)
    buffer = io.BytesIO()
    qr.save(buffer, format='PNG')
    buffer.seek(0)

    # Encode as base64
    image_base64 = base64.b64encode(buffer.read()).decode('utf-8')
    return Response({'qr_code_base64': image_base64})


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
