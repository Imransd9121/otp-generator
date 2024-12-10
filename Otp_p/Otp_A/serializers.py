from rest_framework import serializers
from django.utils.timezone import now, timedelta
from .models import User, OTP
from django.core.mail import send_mail
import random

class RegistrationSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=50)
    email = serializers.EmailField()
    phone_number = serializers.CharField(max_length=15)
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def create(self, validated_data):
        email = validated_data['email']
        otp_code = str(random.randint(100000, 999999))
        expires_at = now() + timedelta(minutes=5)

        # Save OTP
        OTP.objects.create(email=email, otp=otp_code, expires_at=expires_at)

        # Send email
        send_mail(
            "Your OTP Code",
            f"Your OTP code is {otp_code}. It expires in 5 minute.",
            "from@example.com",
            [email],
        )

        return validated_data


class OTPValidationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

    def validate(self, data):
        email = data['email']
        otp = data['otp']

        try:
            otp_obj = OTP.objects.get(email=email, otp=otp)
        except OTP.DoesNotExist:
            raise serializers.ValidationError("Invalid OTP.")

        if otp_obj.is_expired():
            raise serializers.ValidationError("OTP has expired.")

        return data

    def create(self, validated_data):
        email = validated_data['email']
        otp_obj = OTP.objects.get(email=email)
        otp_obj.delete()  # Remove OTP after successful validation

        user_data = self.context['user_data']
        user = User.objects.create_user(**user_data)
        user.is_active = True
        user.save()
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        from django.contrib.auth import authenticate

        email = data['email']
        password = data['password']
        user = authenticate(email=email, password=password)

        if not user:
            raise serializers.ValidationError("Invalid email or password.")

        if not user.is_active:
            raise serializers.ValidationError("Account is not active.")

        return {"user": user}


class ResetPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)