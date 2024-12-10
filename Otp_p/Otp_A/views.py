from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from .serializers import RegistrationSerializer, OTPValidationSerializer, LoginSerializer
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
import random
from django.core.cache import cache  # Using cache for OTP storage
from django.core.mail import send_mail
from django.conf import settings
import uuid
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

# class RegistrationView(APIView):
#     @swagger_auto_schema(
#         operation_description="Register a new user by sending an OTP to their email.",
#         request_body=openapi.Schema(
#             type=openapi.TYPE_OBJECT,
#             properties={
#                 'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email'),
#                 'username': openapi.Schema(type=openapi.TYPE_STRING, description='Username'),
#                 'password': openapi.Schema(type=openapi.TYPE_STRING, description='Password'),
#                 'phone_number': openapi.Schema(type=openapi.TYPE_STRING, description='Phone number (optional)', required=False),
#             },
#             required=['email', 'username', 'password']
#         ),
#         responses={
#             200: openapi.Response(description="OTP sent successfully."),
#             400: "Invalid input or user already exists.",
#         }
#     )
#     def post(self, request, *args, **kwargs):
#         serializer = RegistrationSerializer(data=request.data)
#         if serializer.is_valid():
#             registration_data = serializer.validated_data
#             email = registration_data['email']

#             # Check if the user with the given email already exists
#             if User.objects.filter(email=email).exists():
#                 return Response(
#                     {"message": "You already have an account. Please go to log in."},
#                     status=status.HTTP_400_BAD_REQUEST,
#                 )

#             # Generate a unique key for storing the data temporarily
#             cache_key = f"registration_{uuid.uuid4()}"
#             cache.set(cache_key, registration_data, timeout=300)  # Data expires in 5 minutes

#             # Generate OTP
#             otp = str(random.randint(100000, 999999))
#             cache.set(f"otp_{email}", otp, timeout=300)  # OTP expires in 5 minutes

#             # Send OTP to the user's email
#             self.send_otp_to_email(email, otp)

#             return Response(
#                 {
#                     "message": "OTP sent successfully. Please verify.",
#                     "cache_key": cache_key,
#                 },
#                 status=status.HTTP_200_OK,
#             )

#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


#     @staticmethod
#     def send_otp_to_email(email, otp):
#         """
#         Sends an OTP to the user's email.
#         """
#         subject = "Your OTP for Registration"
#         message = f"Your OTP for registration is: {otp}\nThis OTP is valid for 5 minutes."
#         from_email = settings.DEFAULT_FROM_EMAIL

#         # Send the email
#         send_mail(subject, message, from_email, [email])


class RegistrationView(APIView):
    @swagger_auto_schema(
        operation_description="User registration with email and password",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email'),
                'username': openapi.Schema(type=openapi.TYPE_STRING, description='Username'),
                'phone_number': openapi.Schema(type=openapi.TYPE_STRING, description='Phone number (optional)'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description='Password'),
                'confirm_password':openapi.Schema(type=openapi.TYPE_STRING, description='Confirm_Password'),
            },
            required=['email', 'username', 'password']  # Only the required fields should be here
        ),
        responses={
            200: openapi.Response(
                description="OTP sent for verification",
                examples={
                    "application/json": {
                        "message": "OTP sent successfully. Please verify.",
                        "cache_key": "CACHE_KEY_HERE"
                    }
                }
            ),
            400: "Bad request (validation errors)"
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid():
            registration_data = serializer.validated_data
            email = registration_data['email']

            # Check if the user with the given email already exists
            if User.objects.filter(email=email).exists():
                return Response(
                    {"message": "You already have an account. Please go to log in."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Generate a unique key for storing the data temporarily
            cache_key = f"registration_{uuid.uuid4()}"
            cache.set(cache_key, registration_data, timeout=300)  # Data expires in 5 minutes

            # Generate OTP
            otp = str(random.randint(100000, 999999))
            cache.set(f"otp_{email}", otp, timeout=300)  # OTP expires in 5 minutes

            # Send OTP to the user's email
            self.send_otp_to_email(email, otp)

            return Response(
                {
                    "message": "OTP sent successfully. Please verify.",
                    "cache_key": cache_key,
                },
                status=status.HTTP_200_OK,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @staticmethod
    def send_otp_to_email(email, otp):
        """
        Sends an OTP to the user's email.
        """
        subject = "Your OTP for Registration"
        message = f"Your OTP for registration is: {otp}\nThis OTP is valid for 5 minutes."
        from_email = settings.DEFAULT_FROM_EMAIL

        # Send the email
        send_mail(subject, message, from_email, [email])

class ValidateOTPView(APIView):
    @swagger_auto_schema(
        operation_description="Validate the OTP and complete user registration.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email'),
                'otp': openapi.Schema(type=openapi.TYPE_STRING, description='One-time password sent to email'),
                'cache_key': openapi.Schema(type=openapi.TYPE_STRING, description='Cache key received from registration step'),
            },
            required=['email', 'otp', 'cache_key']
        ),
        responses={
            200: openapi.Response(description="OTP verified successfully, user registered."),
            400: "OTP validation failed or data expired.",
        }
    )
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        otp = request.data.get('otp')
        cache_key = request.data.get('cache_key')  # Get cache_key from the request

        # Check if cache_key is provided
        if not cache_key:
            return Response({"error": "Cache key is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Retrieve registration data from cache using cache_key
        registration_data = cache.get(cache_key)
        
        if not registration_data:
            return Response({"error": "OTP data not found or expired."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate OTP from cache
        stored_otp = cache.get(f"otp_{email}")  # Retrieve the OTP stored in cache for this email
        if not stored_otp:
            return Response({"error": "OTP has expired."}, status=status.HTTP_400_BAD_REQUEST)

        if otp != stored_otp:
            return Response({"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)

        # OTP is correct, now save user data
        user = User.objects.create_user(
            email=registration_data['email'],
            username=registration_data['username'],
            password=registration_data['password'],
            phone_number=registration_data.get('phone_number', None),  # Adjust for the phone_number field
        )

        # Once registered, clear the registration data and OTP from cache
        cache.delete(cache_key)
        cache.delete(f"otp_{email}")

        return Response({"message": "OTP verified successfully, user registered."}, status=status.HTTP_200_OK)

class LoginView(APIView):

    @swagger_auto_schema(
        operation_description="Login API to generate JWT tokens",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description='User password'),
            },
            required=['email', 'password']
        ),
        responses={
            200: openapi.Response(
                description="Tokens generated successfully",
                examples={
                    "application/json": {
                        "detail": "Login successful.",
                        "access_token": "ACCESS_TOKEN_HERE",
                        "refresh_token": "REFRESH_TOKEN_HERE"
                    }
                }
            ),
            400: "Invalid credentials",
        }
    )
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            refresh = RefreshToken.for_user(user)
            
            # Include user details in the response
            user_details = {
                "email": user.email,
                "username": user.username,
                'Phone_number':user.phone_number,  # Assuming you have a user_type field in your model
                  # Include any other fields you want
            }

            return Response({
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "user": user_details,  # Add user details here
            }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




class ForgotPasswordView(APIView):
    @swagger_auto_schema(
        operation_description="Request an OTP to reset the password.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email'),
            },
            required=['email']
        ),
        responses={
            200: openapi.Response(description="OTP sent to email."),
            400: "Email not registered.",
        }
    )
    def post(self, request):
        email = request.data.get('email')
        
        # Check if the email is registered
        try:
            user = get_user_model().objects.get(email=email)
        except get_user_model().DoesNotExist:
            return Response({"error": "Email is not registered. Please go to the registration page."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Generate OTP
        otp = str(random.randint(100000, 999999))
        
        # Store the OTP in cache (valid for 5 minutes)
        cache.set(f"otp_{email}", otp, timeout=300)  # OTP expires in 5 minutes
        
        # Send OTP to the user's email
        self.send_otp_to_email(email, otp)
        
        return Response({"message": "OTP sent to your email. Please verify to reset your password."}, status=status.HTTP_200_OK)
    
    def send_otp_to_email(self, email, otp):
        """
        Sends an OTP to the user's email.
        """
        subject = "Password Reset OTP"
        message = f"Your OTP for resetting your password is: {otp}\nThis OTP is valid for 5 minutes."
        from_email = settings.DEFAULT_FROM_EMAIL
        
        send_mail(subject, message, from_email, [email])



class VerifyOTPView(APIView):
    @swagger_auto_schema(
        operation_description="Verify OTP for password reset.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email'),
                'otp': openapi.Schema(type=openapi.TYPE_STRING, description='One-time password sent to email'),
            },
            required=['email', 'otp']
        ),
        responses={
            200: openapi.Response(description="OTP verified successfully."),
            400: "OTP expired or invalid.",
        }
    )
    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')
        
        # Check if OTP exists in cache
        stored_otp = cache.get(f"otp_{email}")
        
        if not stored_otp:
            return Response({"error": "OTP expired or not found. Please request a new one."}, status=status.HTTP_400_BAD_REQUEST)
        
        if otp != stored_otp:
            return Response({"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)
        
        # OTP is valid, proceed to allow the user to reset password
        return Response({"message": "OTP verified successfully. Please provide a new password."}, status=status.HTTP_200_OK)


class ResetPasswordView(APIView):
    @swagger_auto_schema(
        operation_description="Reset password using a verified OTP.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email'),
                'new_password': openapi.Schema(type=openapi.TYPE_STRING, description='New password'),
                'confirm_password': openapi.Schema(type=openapi.TYPE_STRING, description='Confirm new password'),
                'otp': openapi.Schema(type=openapi.TYPE_STRING, description='One-time password for verification'),  # OTP field
            },
            required=['email', 'new_password', 'confirm_password', 'otp']
        ),
        responses={
            200: openapi.Response(description="Password reset successfully."),
            400: "Passwords do not match, OTP invalid, or email not registered.",
        }
    )
    def post(self, request):
        email = request.data.get('email')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')
        otp = request.data.get('otp')  # Get OTP from request

        # Check if the passwords match
        if new_password != confirm_password:
            return Response({"error": "Passwords do not match."}, status=status.HTTP_400_BAD_REQUEST)

        # Validate the email is registered
        try:
            user = get_user_model().objects.get(email=email)
        except get_user_model().DoesNotExist:
            return Response({"error": "Email not found. Please request a new OTP."}, status=status.HTTP_400_BAD_REQUEST)

        # Validate the OTP
        cached_otp = cache.get(f"otp_{email}")
        if not cached_otp or cached_otp != otp:
            return Response({"error": "Invalid or expired OTP."}, status=status.HTTP_400_BAD_REQUEST)

        # Save the new password
        user.set_password(new_password)
        user.save()

        # Clear OTP from cache (as password is now reset)
        cache.delete(f"otp_{email}")

        return Response({"message": "Password reset successfully."}, status=status.HTTP_200_OK)