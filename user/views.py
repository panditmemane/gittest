import datetime
import random
import uuid

from django.contrib.auth.hashers import check_password
from django.db.transaction import atomic
from rest_framework.filters import SearchFilter
from rest_framework.generics import ListAPIView, RetrieveAPIView, RetrieveUpdateAPIView

from rest_framework.views import APIView
from django.http import JsonResponse
from rest_framework import status

from neeri_recruitment_portal.helpers import (
    send_otp,
    send_verification_mail,
    send_forget_password_mail,
    send_password_mail,
)
from neeri_recruitment_portal.settings import BASE_URL, ACCOUNT_LOCKED_TIME
from user.models import (
    User,
    RoleMaster,
    UserRoles,
    UserProfile,
    Location,
    UserEducationDetails,
    UserExperienceDetails,
    UserLanguages,
    UserReference,
    NeeriRelation,
    OverseasVisits,
    PublishedPapers,
    ProfessionalTraining,
    UserDocuments,
    OtherInformation,
    UserPermissions,
    NeeriUserProfile,
    MentorMaster,
    Trainee,
    RelaxationMaster,
    RelaxationCategoryMaster,
    UserAuthentication,
)
from job_posting.models import (
    UserJobPositions,
    JobDocuments,
    JobPosting,
    FeeMaster,
    PositionQualificationMapping,
)
from user.serializer import (
    UserSerializer,
    AuthTokenCustomSerializer,
    CustomUserSerializer,
    ApplicantUserPersonalInformationSerializer,
    LocationSerializer,
    UserEducationDetailsSerializer,
    UserExperienceDetailsSerializer,
    NeeriRelationSerializer,
    OverseasVisitsSerializer,
    LanguagesSerializer,
    ReferencesSerializer,
    PublishedPapersSerializer,
    ProfessionalTrainingSerializer,
    UserProfilePreviewSerializer,
    OtherInformationSerializer,
    NeeriUsersSerializer,
    CompareApplicantSerializer,
    RoleMasterSerializer,
    MentorMasterSerializer,
    TraineeSerializer,
    RelaxationMasterSerializer,
    RelaxationCategoryMasterSerializer,
    ApplicantIsFresherSerializer,
    UserDocumentsSerializer,
    ApplicantIsAddressSameSerializer,
    UserAuthenticationSerializer,
)
from job_posting.serializer import (
    ApplicantJobPositionsSerializer,
    PositionQualificationMappingSerializer,
)
from knox.views import LoginView as KnoxLoginView
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import AllowAny
from neeri_recruitment_portal.messeges import (
    INACTIVE_ACCOUNT_ERROR,
    INACTIVE_EMAIL_ERROR,
    INACTIVE_MOBILE_ERROR,
    INACTIVE_EMAIL_MOBILE_ERROR,
    INACTIVE_LOCKED_ERROR,
    INACTIVE_SUSPENDED_ERROR,
    INVALID_PASSWORD_ERROR,
)
from django.contrib.auth import login, logout
from rest_framework.response import Response
from django.views.decorators.csrf import csrf_exempt
from knox.views import LogoutView as KnoxLogoutView
import os
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.conf import settings
from django.core.mail import send_mail


class LoginResponseViewMixin:
    def get_post_response_data(self, request, token, instance):

        print("INSIDE LoginResponseViewMixin")

        serializer = self.response_serializer_class(
            data={
                "expiry": self.format_expiry_datetime(instance.expiry),
                "token": token,
                "user": self.get_user_serializer_class()(
                    request.user, context=self.get_context()
                ).data,
            }
        )
        # Note: This serializer was only created to easily document on swagger
        # the return of this endpoint, so the validation it's not really used
        serializer.is_valid(raise_exception=True)
        print("DONE")
        return serializer.initial_data


class LoginView(KnoxLoginView, LoginResponseViewMixin):
    """
    Login view adapted for our needs. Since by default all user operations
    need to be authenticated, we need to explicitly set it to AllowAny.
    """

    permission_classes = [
        AllowAny,
    ]

    @csrf_exempt
    def post(self, request, *args, **kwargs):
        data = request.data
        user = User.objects.filter(email__exact=data["email"]).first()
        password = data["password"]
        check_pwd = check_password(password, user.password)
        attempts = UserAuthentication.objects.get(user=user)
        print("datetime.datetime.now()", datetime.datetime.now())
        print("attempts.account_lock_expiry", attempts.account_lock_expiry)

        if datetime.datetime.now() >= attempts.account_lock_expiry:
            attempts.is_locked = False
            attempts.save()
        if not check_pwd:
            print(
                "attempts.wrong_login_attempt---------->", attempts.wrong_login_attempt
            )
            attempts.wrong_login_attempt = attempts.wrong_login_attempt + 1
            attempts.save()
            print("attempts.login_attempt---------->", attempts.wrong_login_attempt)
            login_attempt = attempts.wrong_login_attempt
            attempts_left = 5 - login_attempt

            if login_attempt > 4:
                attempts.is_locked = True
                attempts.save()
                # print("unlock_time---------->", datetime.timedelta(minutes=ACCOUNT_LOCKED_TIME))
                # request.session["refresh_account"] = datetime.datetime.now() + datetime.timedelta(
                #     minutes=ACCOUNT_LOCKED_TIME)

                return Response(
                    data={
                        "message": "Account has been locked for multiple wrong Attempts. Try after sometime"
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            return Response(
                data={"message": "Wrong Password.", "attempts_left": attempts_left},
                status=status.HTTP_400_BAD_REQUEST,
            )
        # request.session["refresh_account"] = datetime.datetime.now() + datetime.timedelta(minutes=ACCOUNT_LOCKED_TIME)
        # print("request.session['refresh_account']---------->", request.session["refresh_account"])
        # print("datetime.datetime.now()---------->", datetime.datetime.now())

        else:
            attempts.wrong_login_attempt = 0
            # if datetime.datetime.now() > request.session["refresh_account"]:
            #     attempts.is_locked = False
            #     attempts.save()
            attempts.save()
        roles = [role.role.role_name for role in UserRoles.objects.filter(user=user)]
        permissions = [
            permission.permission.permission_name
            for permission in UserPermissions.objects.filter(
                role__role_name__in=roles
            ).distinct("permission")
        ]
        if "applicant" in roles:
            serializer = AuthTokenCustomSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data["user"]
            # return Response(serializer.data, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(
                data={"message": "You're not authorized to login.."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        authentication = UserAuthentication.objects.get(user=user)

        if (
            not getattr(user, "is_active", None)
            and not authentication.mobile_verified
            and not authentication.email_verified
        ):
            raise AuthenticationFailed(
                INACTIVE_EMAIL_MOBILE_ERROR, code="account_disabled"
            )
        if not getattr(user, "is_active", None) and not authentication.mobile_verified:
            raise AuthenticationFailed(INACTIVE_MOBILE_ERROR, code="account_disabled")
        if not getattr(user, "is_active", None) and not authentication.email_verified:
            raise AuthenticationFailed(INACTIVE_EMAIL_ERROR, code="account_disabled")
        if authentication.is_suspended:
            raise AuthenticationFailed(
                INACTIVE_SUSPENDED_ERROR, code="account_disabled"
            )
        if authentication.is_locked:
            raise AuthenticationFailed(INACTIVE_LOCKED_ERROR, code="account_disabled")

        res = login(request, user)
        print("res", res)

        result = super(LoginView, self).post(request, format=None)
        serializer = UserSerializer(user)
        result.data["user"] = serializer.data
        result.data["roles"] = roles
        result.data["permissions"] = permissions
        return Response(result.data)


class TempLoginView(KnoxLoginView, LoginResponseViewMixin):
    """
    Login view adapted for our needs. Since by default all user operations
    need to be authenticated, we need to explicitly set it to AllowAny.
    """

    permission_classes = [
        AllowAny,
    ]

    @csrf_exempt
    def post(self, request, *args, **kwargs):
        data = request.data
        user = User.objects.get(email__exact=data["email"])
        roles = [role.role.role_name for role in UserRoles.objects.filter(user=user)]
        permissions = [
            permission.permission.permission_name
            for permission in UserPermissions.objects.filter(
                role__role_name__in=roles
            ).distinct("permission")
        ]
        # if 'applicant' in roles:
        serializer = AuthTokenCustomSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        # return Response(serializer.data, status=status.HTTP_400_BAD_REQUEST)
        # else:
        #     return Response(data={"message": "You're not authorized to login.."}, status=status.HTTP_400_BAD_REQUEST)

        if not getattr(user, "is_active", None):
            raise AuthenticationFailed(INACTIVE_ACCOUNT_ERROR, code="account_disabled")
        res = login(request, user)
        result = super(TempLoginView, self).post(request, format=None)
        serializer = UserSerializer(user)
        # authentication = UserAuthentication.objects.get(user=user)
        result.data["user"] = serializer.data
        result.data["roles"] = roles
        result.data["permissions"] = permissions
        # result.data['email_verified'] = authentication.email_verified
        # result.data['mobile_verified'] = authentication.mobile_verified
        return Response(result.data)


class NeeriLoginView(KnoxLoginView, LoginResponseViewMixin):
    """
    For NEERI User
    Login view adapted for our needs. Since by default all user operations
    need to be authenticated, we need to explicitly set it to AllowAny.
    """

    permission_classes = [
        AllowAny,
    ]

    @csrf_exempt
    def post(self, request, *args, **kwargs):
        data = request.data
        user = User.objects.get(email__exact=data["email"])
        roles = [role.role.role_name for role in UserRoles.objects.filter(user=user)]
        permissions = [
            permission.permission.permission_name
            for permission in UserPermissions.objects.filter(
                role__role_name__in=roles
            ).distinct("permission")
        ]

        if not "applicant" in roles:
            serializer = AuthTokenCustomSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data["user"]
            # return Response(serializer.data, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(
                data={"message": "You're not authorized to login.."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not getattr(user, "is_active", None):
            raise AuthenticationFailed(INACTIVE_ACCOUNT_ERROR, code="account_disabled")
        res = login(request, user)
        print("res", res)

        result = super(NeeriLoginView, self).post(request, format=None)
        serializer = UserSerializer(user)
        # authentication = UserAuthentication.objects.get(user=user)
        result.data["user"] = serializer.data
        result.data["roles"] = roles
        result.data["permissions"] = permissions
        # result.data['email_verified'] = authentication.email_verified
        # result.data['mobile_verified'] = authentication.mobile_verified
        return Response(
            result.data,
        )


# class NeeriLoginView(KnoxLoginView, LoginResponseViewMixin):
#     """
#     For NEERI User
#     Login view adapted for our needs. Since by default all user operations
#     need to be authenticated, we need to explicitly set it to AllowAny.
#     """
#     permission_classes = [AllowAny, ]
#
#     @csrf_exempt
#     def post(self, request, *args, **kwargs):
#         data = request.data
#         user = User.objects.get(email__exact=data['email'])
#         roles = [role.role.role_name for role in UserRoles.objects.filter(user=user)]
#         permissions = [permission.permission.permission_name for permission in
#                        UserPermissions.objects.filter(role__role_name__in=roles).distinct('permission')]
#
#         if not 'applicant' in roles:
#             serializer = AuthTokenCustomSerializer(data=request.data)
#             serializer.is_valid(raise_exception=True)
#             user = serializer.validated_data["user"]
#             print('welcome neeri user', serializer.data)
#             # return Response(serializer.data, status=status.HTTP_400_BAD_REQUEST)
#         else:
#             return Response(data={"message": "You're not authorized to login.."}, status=status.HTTP_400_BAD_REQUEST)
#
#         if not getattr(user, "is_active", None):
#             raise AuthenticationFailed(INACTIVE_ACCOUNT_ERROR, code="account_disabled")
#         res = login(request, user)
#         print('res', res)
#
#         result = super(NeeriLoginView, self).post(request, format=None)
#         serializer = UserSerializer(user)
#         # authentication = UserAuthentication.objects.get(user=user)
#         result.data['user'] = serializer.data
#         result.data['roles'] = roles
#         result.data['permissions'] = permissions
#         # result.data['email_verified'] = authentication.email_verified
#         # result.data['mobile_verified'] = authentication.mobile_verified
#         return Response(result.data, )


class LogoutView(KnoxLogoutView):
    @csrf_exempt
    def post(self, request, *args, **kwargs):
        request._auth.delete()
        logout(request)
        return Response(
            data={"messege": "Logged out successfully"},
        )


class UserRegistrationView(APIView):
    permission_classes = [
        AllowAny,
    ]

    def post(self, request, *args, **kwargs):
        mobile_no = self.request.data["mobile_no"]
        email = self.request.data["email"]
        password = self.request.data["password"]
        role = RoleMaster.objects.get(role_name__exact="applicant")
        if User.objects.filter(email=email).exists():
            return JsonResponse(
                data={"messege": "User Already Exist"},
            )
        elif User.objects.filter(mobile_no=mobile_no).exists():
            return JsonResponse(
                data={"messege": "Mobile Number Already Exist"},
            )
        else:
            user = User.objects.create_user(mobile_no, email, password)
            user.is_active = False
            user.save()
            user_mobile_otp = random.randint(100000, 999999)
            user_email_token = str(uuid.uuid4())
            # user_sms_token = str(uuid.uuid4())
            UserAuthentication.objects.create(
                user=user, email_token=user_email_token, mobile_otp=user_mobile_otp
            )
            print("user.is_active---------->", user.is_active)
            UserRoles.objects.create(role=role, user=user)
            roles = [
                role.role.role_name for role in UserRoles.objects.filter(user=user)
            ]
            permissions = [
                permission.permission.permission_name
                for permission in UserPermissions.objects.filter(
                    role__role_name__in=roles
                ).distinct("permission")
            ]
            serializer = UserSerializer(user)
            result = {}
            result["user"] = serializer.data
            result["roles"] = roles
            result["permissions"] = permissions
            # send_otp(mobile_no, user_mobile_otp)
            send_verification_mail(email, user_email_token)
            return JsonResponse(data=result, safe=False)


def verify_sms(request, user_mobile_otp):
    try:
        is_token_expired = UserAuthentication.objects.filter(
            mobile_otp=user_mobile_otp
        ).first()
        if not is_token_expired:
            return JsonResponse(
                data={"message": "Link Expired, request again."},
            )
        if datetime.datetime.now() >= is_token_expired.mobile_otp_expiry:
            is_token_expired.mobile_otp = None
            is_token_expired.save()
            return JsonResponse(
                data={"message": "Link Expired, request again."},
            )
        else:

            if is_token_expired:

                try:
                    user_sms_auth = UserAuthentication.objects.filter(
                        mobile_otp=user_mobile_otp
                    ).first()
                    if user_sms_auth:
                        if user_sms_auth.mobile_verified:
                            return JsonResponse(
                                data={"message": "Your mobile is already verified."},
                            )
                        user_sms_auth.mobile_verified = True
                        user_sms_auth.mobile_otp = None
                        user_sms_auth.save()
                        if user_sms_auth.email_verified:
                            user_sms_auth.user.is_active = True
                            user_sms_auth.user.save()
                            return JsonResponse(
                                data={"message": "Your account has been verified."},
                            )
                        return JsonResponse(
                            data={"message": "Your mobile has been verified."},
                        )
                    # if user_sms_auth.mobile_verified and user_sms_auth.email_verified:
                    #     user_sms_auth.user.is_active = True
                    #     user_sms_auth.user.save()
                    #     return JsonResponse(
                    #         data={"message": "Your account has been verified."},
                    #     )
                    else:
                        return JsonResponse(
                            status=status.HTTP_400_BAD_REQUEST,
                        )
                except Exception as e:
                    print(e)
                    return JsonResponse(
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            else:
                return JsonResponse(
                    data={"message": "Token is invalid, request again to verify."},
                )
    except Exception as e:
        print(e)
        return JsonResponse(
            status=status.HTTP_400_BAD_REQUEST,
        )


def verify_email(request, user_email_token):

    try:
        is_token_expired = UserAuthentication.objects.filter(
            email_token=user_email_token
        ).first()
        if not is_token_expired:
            return JsonResponse(
                data={"message": "Link Expired, request again."},
            )
        if datetime.datetime.now() >= is_token_expired.email_otp_expiry:
            is_token_expired.email_token = None
            is_token_expired.save()
            return JsonResponse(
                data={"message": "Link Expired."},
            )
        else:

            if is_token_expired:
                try:
                    user_email_auth = UserAuthentication.objects.filter(
                        email_token=user_email_token
                    ).first()
                    if user_email_auth:
                        if user_email_auth.email_verified:
                            return JsonResponse(
                                data={"message": "Your email is already verified."},
                            )
                        user_email_auth.email_verified = True
                        user_email_auth.save()

                        user_email_auth.email_token = None
                        user_email_auth.save()
                        # if user_email_auth.sms_verified:
                        #     user_email_auth.user.is_active = True
                        #     user_email_auth.user.save()
                        #     return JsonResponse(
                        #         data={"message": "Your account has been verified."},
                        #     )
                        # else:
                        #     return JsonResponse(
                        #         data={"message": "Mobile Number is not verified."},
                        #     )
                        return JsonResponse(
                            data={"message": "Your email has been verified."},
                        )
                    else:
                        return JsonResponse(
                            status=status.HTTP_400_BAD_REQUEST,
                        )
                except Exception as e:
                    print(e)
                    return JsonResponse(
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            else:
                return JsonResponse(
                    data={"message": "Token is invalid, request again to verify."},
                )
    except Exception as e:
        print(e)
        return JsonResponse(
            status=status.HTTP_400_BAD_REQUEST,
        )


class UserListView(ListAPIView):
    serializer_class = UserSerializer
    queryset = User.objects.filter(is_deleted=False)


class RetrieveUserView(RetrieveAPIView):
    queryset = User.objects.filter(is_deleted=False)
    serializer_class = CustomUserSerializer
    lookup_field = "user_id"
    lookup_url_kwarg = "id"


class CreateUserView(APIView):
    def post(self, request, *args, **kwargs):
        data = self.request.data
        mobile_no = data["mobile_no"]
        email = data["email"]
        if User.objects.filter(email=email).exists():
            return JsonResponse(
                data={"messege": "User Already Exist"},
            )
        elif User.objects.filter(mobile_no=mobile_no).exists():
            return JsonResponse(
                data={"messege": "User Already Exist"},
            )
        else:
            user = User.objects.create_user(mobile_no=mobile_no, email=email)
            serializer = CustomUserSerializer(user, data=data)
            serializer.is_valid(raise_exception=True)
            serializer.save(instance=user, validated_data=data)
            return Response(serializer.data)


class NeeriUserSearchListView(ListAPIView):
    queryset = NeeriUserProfile.objects.all()
    serializer_class = NeeriUsersSerializer
    filter_backends = [SearchFilter]
    search_fields = ("user__first_name", "user__last_name", "user__mobile_no")


class NeeriUserListView(APIView):
    def get(self, request, *args, **kwargs):
        neeri_user = NeeriUserProfile.objects.filter(is_deleted=False)
        serializer = NeeriUsersSerializer(neeri_user, many=True)
        return Response(serializer.data)


class CreateNeeriUserView(APIView):
    def get(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = NeeriUserProfile.objects.get(user_id=id, is_deleted=False)
        serializer = NeeriUsersSerializer(user)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        data = self.request.data
        mobile_no = data["mobile_no"]
        email = data["email"]
        # password = data['password']
        if User.objects.filter(email=email).exists():
            return JsonResponse(
                data={"message": "email Already Exist"},
            )
        elif User.objects.filter(mobile_no=mobile_no).exists():
            return JsonResponse(
                data={"message": "mobile no. Already Exist"},
            )
        else:
            # user = User.objects.create_user(mobile_no=mobile_no, email=email, password=password)
            serializer = NeeriUsersSerializer(data=data)
            serializer.is_valid(raise_exception=True)
            password = User.objects.make_random_password()
            result = serializer.save(validated_data=data, password=password)
            neeri_user_profile = NeeriUserProfile.objects.get(user=result)
            authuser = User.objects.filter(
                user_id=neeri_user_profile.user.user_id
            ).first()
            UserAuthentication.objects.create(user=authuser)
            send_password_mail(neeri_user_profile.user.email, password)
            result_serializer = NeeriUsersSerializer(neeri_user_profile)
            return Response(result_serializer.data)

    def put(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = NeeriUserProfile.objects.get(user_id=id)
        data = self.request.data
        serializer = NeeriUsersSerializer(user, data=data)
        serializer.is_valid(raise_exception=True)
        serializer.update(instance=user, validated_data=data)
        return Response(serializer.data)

    def delete(self, request, *args, **kwargs):
        try:
            id = self.kwargs["id"]
            user = User.objects.get(user_id=id)
            user.is_deleted = True
            user.save()
            n_user = NeeriUserProfile.objects.get(user__user_id=id)
            n_user.is_deleted = True
            n_user.save()
            return Response(
                data={"message": "Neeri User Deleted Successfully.(soft deleted)"},
            )
        except:
            return Response(
                data={"message": "Neeri User Not Found."},
                status=status.HTTP_404_NOT_FOUND,
            )


class UpdateUserView(APIView):
    def put(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        data = self.request.data
        serializer = CustomUserSerializer(user, data=data)
        serializer.is_valid(raise_exception=True)
        serializer.update(instance=user, validated_data=data)
        return Response(serializer.data)


class DeleteUserView(APIView):
    def delete(self, request, *args, **kwargs):
        try:
            id = self.kwargs["id"]
            user = User.objects.get(user_id=id)
            user.is_deleted = True
            user.save()
            return Response(
                data={"messege": "User Deleted Successfully."},
            )
        except:
            return Response(
                data={"messege": "User Not Found."}, status=status.HTTP_404_NOT_FOUND
            )


class ForgotPassword(APIView):

    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        data = self.request.data
        email = data["email"]
        print("email--------------->", email)
        try:
            user = User.objects.get(email=email)
            print("user--------------->", user)

            if user:
                # Need to send Email with a link where user can reset password.
                user_reset_token = str(uuid.uuid4())
                print("user--------------->", user_reset_token, user.email)

                auth = UserAuthentication.objects.filter(user=user).first()
                auth.reset_token = user_reset_token
                auth.save()
                send_forget_password_mail(user.email, user_reset_token)

                return Response(
                    data={
                        "message": "Link sent to your registered Email.",
                        "email": user.email,
                    },
                )
        except:
            return Response(
                data={"message": "Email not found, enter valid email."},
                status=status.HTTP_404_NOT_FOUND,
            )


class MobileOTP(APIView):
    permission_classes = [
        AllowAny,
    ]

    def post(self, request, *args, **kwargs):
        data = self.request.data
        user_otp = data["user_otp"]
        token = str(self.kwargs["id"])
        # auth = UserAuthentication.objects.filter(reset_token=token).first()
        try:
            is_token_expired = UserAuthentication.objects.filter(
                mobile_otp=token
            ).first()
            print("is_token_expired----------->", is_token_expired)
            if not is_token_expired:
                return JsonResponse(
                    data={"message": "OTP Expired or invalid."},
                )
            if datetime.datetime.now() >= is_token_expired.mobile_otp_expiry:
                print(
                    "datetime.datetime.now() >= is_token_expired.mobile_otp_expiry----->",
                    datetime.datetime.now(),
                    is_token_expired.mobile_otp_expiry,
                )
                # e = UserAuthentication.objects.get(user=is_token_expired)
                print(
                    "is_token_expired.reset_token----------->",
                    is_token_expired.mobile_otp,
                )
                is_token_expired.mobile_otp = None
                is_token_expired.save()
                print(
                    "is_token_expired.mobile_otp----------->",
                    is_token_expired.mobile_otp,
                )

                return JsonResponse(
                    data={"message": "OTP Expired, request again"},
                )
            else:

                if is_token_expired:
                    try:
                        # user_obj = User.objects.get(user_id=is_token_expired.user.user_id)
                        if user_otp == is_token_expired.mobile_otp:
                            is_token_expired.mobile_verified = True
                            is_token_expired.mobile_otp = None
                            is_token_expired.save()
                        else:
                            return Response(
                                data={"message": "Please enter a valid OTP."},
                            )
                        print(
                            "is_token_expired.mobile_otp------------->",
                            is_token_expired.mobile_otp,
                        )
                        if is_token_expired.email_verified:
                            is_token_expired.user.is_active = True
                            is_token_expired.user.save()
                            return JsonResponse(
                                data={"message": "Your account has been verified."},
                            )
                        return Response(
                            data={"message": "Your mobile has been verified."},
                        )
                    except Exception as e:
                        print(e)
                        return JsonResponse(
                            status=status.HTTP_400_BAD_REQUEST,
                        )
                else:
                    return Response(
                        data={"message": "OTP has been expired. Please request again."},
                    )
        except Exception as e:
            print(e)
            return JsonResponse(
                status=status.HTTP_400_BAD_REQUEST,
            )


class UpdateMobileOTP(APIView):
    permission_classes = [
        AllowAny,
    ]

    def post(self, request, *args, **kwargs):
        data = self.request.data
        user_otp = data["user_otp"]
        token = str(self.kwargs["id"])
        # auth = UserAuthentication.objects.filter(reset_token=token).first()
        try:
            is_token_expired = UserAuthentication.objects.filter(
                mobile_otp=token
            ).first()
            print("is_token_expired----------->", is_token_expired)
            if not is_token_expired:
                return JsonResponse(
                    data={"message": "OTP Expired or invalid."},
                )
            if datetime.datetime.now() >= is_token_expired.mobile_otp_expiry:
                print(
                    "datetime.datetime.now() >= is_token_expired.mobile_otp_expiry----->",
                    datetime.datetime.now(),
                    is_token_expired.mobile_otp_expiry,
                )
                # e = UserAuthentication.objects.get(user=is_token_expired)
                print(
                    "is_token_expired.reset_token----------->",
                    is_token_expired.mobile_otp,
                )
                is_token_expired.mobile_otp = None
                is_token_expired.save()
                print(
                    "is_token_expired.mobile_otp----------->",
                    is_token_expired.mobile_otp,
                )

                return JsonResponse(
                    data={"message": "OTP Expired, request again"},
                )
            else:

                if is_token_expired:
                    try:
                        user_obj = User.objects.get(
                            user_id=is_token_expired.user.user_id
                        )
                        if user_otp == is_token_expired.mobile_otp:
                            is_token_expired.mobile_verified = True
                            is_token_expired.mobile_otp = None
                            is_token_expired.save()
                            print(
                                "request.session['new_mobile_no']----otp---->",
                                request.session["new_mobile_no"],
                            )
                            user_obj.mobile_no = request.session["new_mobile_no"]
                            print("user_obj.mobile_no----otp---->", user_obj.mobile_no)
                            user_obj.save()
                        else:
                            return Response(
                                data={"message": "Please enter a valid OTP."},
                            )
                        print(
                            "is_token_expired.mobile_otp------------->",
                            is_token_expired.mobile_otp,
                        )
                        # request.session['user_id'] = None
                        request.session["new_mobile_no"] = None
                        print(
                            "request.session['new_mobile_no']----------------->",
                            request.session["new_mobile_no"],
                        )

                        return Response(
                            data={"message": "Your mobile has been verified."},
                        )
                    except Exception as e:
                        print(e)
                        return JsonResponse(
                            status=status.HTTP_400_BAD_REQUEST,
                        )
                else:
                    return Response(
                        data={"message": "OTP has been expired. Please request again."},
                    )
        except Exception as e:
            print(e)
            return JsonResponse(
                status=status.HTTP_400_BAD_REQUEST,
            )


class ResetPassword(APIView):
    permission_classes = [
        AllowAny,
    ]

    def post(self, request, *args, **kwargs):
        data = self.request.data
        password = data["password"]
        confirm_password = data["confirm_password"]
        token = str(self.kwargs["token"])
        # auth = UserAuthentication.objects.filter(reset_token=token).first()
        try:
            is_token_expired = UserAuthentication.objects.filter(
                reset_token=token
            ).first()
            print("is_token_expired.reset_token----------->", is_token_expired)
            if not is_token_expired:
                return JsonResponse(
                    data={"message": "Link Expired, request again"},
                )
            if datetime.datetime.now() >= is_token_expired.reset_otp_expiry:
                print(
                    "datetime.datetime.now() >= is_token_expired.reset_otp_expiry----->",
                    datetime.datetime.now(),
                    is_token_expired.reset_otp_expiry,
                )
                # e = UserAuthentication.objects.get(user=is_token_expired)
                print(
                    "is_token_expired.reset_token----------->",
                    is_token_expired.reset_token,
                )
                is_token_expired.reset_token = None
                is_token_expired.save()
                print(
                    "is_token_expired.reset_token----------->",
                    is_token_expired.reset_token,
                )

                return JsonResponse(
                    data={"message": "Link Expired, request again"},
                )
            else:

                if is_token_expired:
                    try:
                        user_obj = User.objects.get(
                            user_id=is_token_expired.user.user_id
                        )
                        if password == confirm_password:
                            user_obj.set_password(password)
                            user_obj.save()
                            is_token_expired.reset_token = None
                            is_token_expired.save()
                        else:
                            return Response(
                                data={
                                    "message": "Password and Confirm password are different."
                                },
                            )
                        print(
                            "auth.reset_token------------->",
                            is_token_expired.reset_token,
                        )
                        return Response(
                            data={"message": "Password reset Successfully."},
                        )
                    except Exception as e:
                        print(e)
                        return JsonResponse(
                            status=status.HTTP_400_BAD_REQUEST,
                        )
                else:
                    return Response(
                        data={
                            "message": "Token has been expired. Please request again."
                        },
                    )
        except Exception as e:
            print(e)
            return JsonResponse(
                status=status.HTTP_400_BAD_REQUEST,
            )


class ChangePassword(APIView):
    def put(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        data = self.request.data
        old_password = data["old_password"]
        new_password = data["new_password"]
        confirm_password = data["confirm_password"]
        auth = User.objects.filter(user_id=id).first()
        if auth:
            user_obj = User.objects.get(user_id=auth.user_id)
            print("user_obj.password------------>", user_obj.password)
            print(
                "check_password---------->",
                check_password(old_password, user_obj.password),
            )
            checked_pwd = check_password(old_password, user_obj.password)
            if checked_pwd:
                if new_password == confirm_password:
                    user_obj.set_password(new_password)
                    user_obj.save()
                else:
                    return Response(
                        data={
                            "message": "Password and Confirm Password are different."
                        },
                    )
                first_login = UserAuthentication.objects.get(user=user_obj)
                first_login.is_first_login = False
                first_login.save()
                return Response(
                    data={"message": "Password has been Successfully changed."},
                    status=status.HTTP_200_OK,
                )

            return Response(
                data={"message": "Please enter the current password correctly"},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        return Response(
            data={"message": "User Not Found."},
            status=status.HTTP_400_BAD_REQUEST,
        )


class ChangeMobileNumber(APIView):
    def put(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        data = self.request.data
        new_mobile_no = data["new_mobile_no"]
        auth = User.objects.filter(user_id=id).first()
        if auth:
            request.session[
                "new_mobile_no"
            ] = new_mobile_no  # session for new mobile number
            user_obj = User.objects.get(user_id=auth.user_id)
            # request.session['user_id'] = user_obj.user_id # session for user_id
            old_mobile_no = user_obj.mobile_no
            if old_mobile_no == new_mobile_no:
                return Response(
                    data={"message": "Old and New Mobile Number cannot be same."},
                    status=status.HTTP_200_OK,
                )
            user_mobile_otp = random.randint(100000, 999999)
            user_auth = UserAuthentication.objects.get(user=user_obj)
            user_auth.mobile_otp = user_mobile_otp
            user_auth.save()
            print("user_obj.mobile_no------------>", user_obj.mobile_no)
            # send_otp(mobile_no, user_mobile_otp)
            return Response(
                data={
                    "message": "OTP has been sent to your new mobile number, please verify"
                },
                status=status.HTTP_200_OK,
            )
        else:

            return Response(
                data={"message": "User Not Found."},
                status=status.HTTP_400_BAD_REQUEST,
            )


# def ForgotPasswordDef(request, token):
#     context = {}
#
#     try:
#         user_obj = UserAuthentication.objects.filter(reset_token__exact=token).first()
#         context = {'user_id': user_obj.user.user_id}
#
#         if request.method == 'POST':
#             new_password = request.POST.get('new_password')
#             confirm_password = request.POST.get('reconfirm_password')
#             user_id = request.POST.get('user_id')
#
#             if user_id is None:
#                 messages.success(request, 'No user id found.')
#                 return redirect(f'/change-password/{token}/')
#
#             if new_password != confirm_password:
#                 messages.success(request, 'both should  be equal.')
#                 return redirect(f'/change-password/{token}/')
#
#             user_obj = User.objects.get(id=user_id)
#             user_obj.set_password(new_password)
#             user_obj.save()
#             return redirect('/login/')
#
#
#     except Exception as e:
#         print(e)
#     return render(request, 'change-password.html', context)


class RoleMasterView(APIView):
    def get(self, request, *args, **kwargs):
        roles = RoleMaster.objects.filter(is_deleted=False)
        serializer = RoleMasterSerializer(roles, many=True)
        return Response(serializer.data)


class ManageApplicantlistView(APIView):
    def get(self, request, *args, **kwargs):
        try:
            roles = UserRoles.objects.select_related("user__user_auth").filter(
                role__role_name="applicant"
            )
            user_auth_instances = [role.user.user_auth for role in roles]
            serializer = UserAuthenticationSerializer(user_auth_instances, many=True)
            return Response(serializer.data, status=200)
        except Exception as e:
            return Response(
                data={"message": str(e)}, status=status.HTTP_401_UNAUTHORIZED
            )

    def delete(self, request, *args, **kwargs):
        try:
            id = self.kwargs["id"]
            user = User.objects.get(user_id=id)
            user.is_deleted = True
            user.save()
            return Response(
                data={"message": "User Deleted Successfully."},
            )
        except Exception as e:
            return Response(
                data={"message": str(e)}, status=status.HTTP_401_UNAUTHORIZED
            )


class ApplicantSuspendStatusView(APIView):
    def get(self, request, *args, **kwargs):
        try:
            id = self.kwargs["id"]
            user = UserAuthentication.objects.filter(user__user_id=id).first()
            serializer = UserAuthenticationSerializer(user)
            return Response(serializer.data)
        except Exception as e:
            return Response(
                data={"message": str(e)}, status=status.HTTP_401_UNAUTHORIZED
            )

    def put(self, request, *args, **kwargs):
        status_data = self.request.data
        applicant_id = self.kwargs["id"]
        try:
            status = UserAuthentication.objects.filter(
                user__user_id=applicant_id
            ).first()
            if status_data["is_suspended"]:
                status.is_suspended = status_data["is_suspended"]
                status.save()
                return Response(status.is_suspended, status=200)
            if not status_data["is_suspended"]:
                status.is_suspended = status_data["is_suspended"]
                status.save()
                return Response(status.is_suspended, status=200)
            else:
                return Response(data={"message": "Detail not found."}, status=401)
        except Exception as e:
            return Response(
                data={"message": str(e)}, status=status.HTTP_401_UNAUTHORIZED
            )


class ApplicantLockedStatusView(APIView):
    def get(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = UserAuthentication.objects.filter(user__user_id=id).first()
        serializer = UserAuthenticationSerializer(user)
        return Response(serializer.data)

    def put(self, request, *args, **kwargs):
        status_data = self.request.data
        applicant_id = self.kwargs["id"]
        try:
            status = UserAuthentication.objects.get(user__user_id=applicant_id)
            if status_data["is_locked"]:
                status.is_locked = status_data["is_locked"]
                status.save()
                return Response(status.is_locked, status=200)
            if not status_data["is_locked"]:
                status.is_locked = status_data["is_locked"]
                status.save()
                return Response(status.is_locked, status=200)
            else:
                return Response(
                    data={"message": "Detail not found inside."}, status=401
                )
        except Exception as e:
            return Response(
                data={"message": str(e)}, status=status.HTTP_401_UNAUTHORIZED
            )


class ApplicantPersonalInformationView(APIView):
    def get(self, request, *args, **kwargs):
        try:
            user = User.objects.get(user_id=self.kwargs["id"])
            try:
                if user.user_profile:
                    serializer = ApplicantUserPersonalInformationSerializer(
                        user.user_profile
                    )
                    return Response(serializer.data)
                else:
                    return Response(
                        data={
                            "messege": "UserProfile does not exist",
                            "isEmpty": "true",
                            "mobile_no": user.mobile_no,
                            "email": user.email,
                        },
                        status=status.HTTP_200_OK,
                    )
            except:
                return Response(
                    data={
                        "messege": "UserProfile does not exist",
                        "isEmpty": "true",
                        "mobile_no": user.mobile_no,
                        "email": user.email,
                    },
                    status=status.HTTP_200_OK,
                )
        except:
            applicant_user = UserProfile.objects.filter(is_deleted=False)
            serializer = ApplicantUserPersonalInformationSerializer(
                applicant_user, many=True
            )
            return Response(serializer.data)


class ApplicantPersonalInformationUpdateView(APIView):
    def put(self, request, *args, **kwargs):
        user = User.objects.get(user_id=self.kwargs["id"])
        data = self.request.data
        user_profile = user.user_profile
        if user_profile:
            serializer = ApplicantUserPersonalInformationSerializer(
                user_profile, data=data
            )
            serializer.is_valid(raise_exception=True)
            serializer.update(instance=user_profile, validated_data=data)
            return Response(serializer.data)
        else:
            return Response(
                data={"message": "UserProfile does not exist"},
                status=status.HTTP_404_NOT_FOUND,
            )


class ApplicantIsFresherUpdateView(APIView):
    def get(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        try:
            if user.user_profile:
                user_profile = user.user_profile
                serializer = ApplicantIsFresherSerializer(user_profile)
                return Response(serializer.data)
        except:
            return Response(
                data={
                    "message": "UserProfile does not exist",
                    "isEmpty": "true",
                    "mobile_no": user.mobile_no,
                    "email": user.email,
                },
            )

    def put(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        data = self.request.data
        try:
            user_profile = user.user_profile
        except:
            return Response(
                data={"message": "UserProfile does not exist"},
            )
        serializer = ApplicantIsFresherSerializer(user_profile, data=data)
        serializer.is_valid(raise_exception=True)
        serializer.update(instance=user_profile, validated_data=data)
        return Response(serializer.data)


class ApplicantIsAddressUpdateView(APIView):
    def get(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        try:
            if user.user_profile:
                user_profile = user.user_profile
                serializer = ApplicantIsAddressSameSerializer(user_profile)
                return Response(serializer.data)
        except:
            return Response(
                data={
                    "message": "UserProfile does not exist",
                    "isEmpty": "true",
                    "mobile_no": user.mobile_no,
                    "email": user.email,
                },
            )

    def put(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        data = self.request.data
        try:
            user_profile = user.user_profile
        except:
            return Response(
                data={"message": "UserProfile does not exist"},
            )
        serializer = ApplicantIsAddressSameSerializer(user_profile, data=data)
        serializer.is_valid(raise_exception=True)
        serializer.update(instance=user_profile, validated_data=data)
        return Response(serializer.data)


class ApplicantPersonalInformationCreateView(APIView):
    def post(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        try:
            if user.user_profile:
                return Response(
                    data={"messege": "UserProfile for Given User Already Exist"}
                )
        except:
            data = self.request.data
            serializer = ApplicantUserPersonalInformationSerializer(data=data)
            serializer.is_valid(raise_exception=True)
            serializer.save(validated_data=data)
            user_profile = UserProfile.objects.get(user=user)
            serializer = ApplicantUserPersonalInformationSerializer(user_profile)
            return Response(serializer.data)


class NeeriPersonalInformation(APIView):
    def get(self, request, *args, **kwargs):
        try:
            id = self.kwargs["id"]
            user = User.objects.get(user_id=id)
            try:
                check_user = NeeriUserProfile.objects.get(user_id=id, is_deleted=False)
                if user.neeri_user_profile and check_user:
                    neeri_user_profile = user.neeri_user_profile
                    serializer = NeeriUsersSerializer(neeri_user_profile)
                    return Response(serializer.data)
            except:
                return Response(
                    data={
                        "message": "Neeri User Profile not created.",
                        "name": user.first_name + " " + user.last_name,
                        "isEmpty": "true",
                        "email": user.email,
                    },
                )
        except:
            neeri_user = NeeriUserProfile.objects.filter(is_deleted=False).order_by(
                "user__first_name"
            )
            serializer = NeeriUsersSerializer(neeri_user, many=True)
            return Response(serializer.data)

    # def post(self, request, *args, **kwargs):
    #     id = self.kwargs['id']
    #     user = User.objects.get(user_id=id)
    #     try:
    #         if user.neeri_user_profile:
    #             return Response(data={"messege": "NeeriUserProfile for Given Neeri User Already Exist"}, )
    #     except:
    #         data = self.request.data
    #         serializer = NeeriUsersSerializer(data=data)
    #         serializer.is_valid(raise_exception=True)
    #         result = serializer.save(validated_data=data)
    #         user_profile = NeeriUserProfile.objects.get(user=user)
    #         serializer = NeeriUsersSerializer(user_profile)
    #         return Response(serializer.data)

    def put(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        data = self.request.data
        try:
            neeri_user_profile = user.neeri_user_profile
        except:
            return Response(
                data={
                    "message": "Neeri User Profile does not exist for the given user, create Neeri User Profile first."
                },
            )
        serializer = NeeriUsersSerializer(neeri_user_profile, data=data)
        serializer.is_valid(raise_exception=True)
        serializer.update(instance=neeri_user_profile, validated_data=data)
        return Response(serializer.data)

    # def delete(self, request, *args, **kwargs):
    #     try:
    #         id = self.kwargs['id']
    #         NeeriUserProfile.objects.get(user__user_id=id).delete()
    #         # user.is_deleted = True
    #         # user.delete()
    #         # user.save()
    #         # print(user)
    #         return Response(data={"message": "Neeri User Deleted Successfully."}, )
    #     except:
    #         return Response(data={"message": "Neeri User Not Found."}, status=status.HTTP_404_NOT_FOUND)


class ApplicantAddressView(APIView):
    def get(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        address_type = self.request.GET["address_type"]
        try:
            if address_type == "local_address" and user.user_profile.local_address:
                location = user.user_profile.local_address
            elif (
                address_type == "permanent_address"
                and user.user_profile.permanent_address
            ):
                location = user.user_profile.permanent_address
            elif address_type == "father_address" and user.user_profile.father_address:
                location = user.user_profile.father_address

            serializer = LocationSerializer(location)
            # serializer.is_valid(raise_exception=True)
            result = serializer.data
            result[
                "is_permenant_address_same_as_local"
            ] = user.user_profile.is_permenant_address_same_as_local
            result[
                "is_father_address_same_as_local"
            ] = user.user_profile.is_father_address_same_as_local
            return Response(result)
        except:
            return Response(
                data={"messege": "Address not created", "isEmpty": "true"},
            )


class ApplicantAddressUpdateView(APIView):
    def put(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        data = self.request.data
        address_type = self.request.GET["address_type"]
        if address_type == "local_address":
            location = user.user_profile.local_address
            serializer = LocationSerializer(location, data=data)
        elif address_type == "permanent_address":
            if "is_permenant_address_same_as_local" in self.request.GET:
                is_permenant_address_same_as_local = self.request.GET[
                    "is_permenant_address_same_as_local"
                ]
                if (
                    is_permenant_address_same_as_local is True
                    or is_permenant_address_same_as_local == "true"
                ):
                    user.user_profile.permanent_address = (
                        user.user_profile.local_address
                    )
                    user.user_profile.is_permenant_address_same_as_local = True
                    user.user_profile.save()
                    location = user.user_profile.permanent_address
                    serializer = LocationSerializer(location, data=data)
                    serializer.is_valid(raise_exception=True)
                    result = serializer.data
                    result[
                        "is_permenant_address_same_as_local"
                    ] = user.user_profile.is_permenant_address_same_as_local
                    result[
                        "is_father_address_same_as_local"
                    ] = user.user_profile.is_father_address_same_as_local
                    return Response(result)
            else:
                location = user.user_profile.permanent_address
                serializer = LocationSerializer(location, data=data)
        else:
            if "is_father_address_same_as_local" in self.request.GET:
                is_father_address_same_as_local = self.request.GET[
                    "is_father_address_same_as_local"
                ]
                if (
                    is_father_address_same_as_local is True
                    or is_father_address_same_as_local == "true"
                ):
                    user.user_profile.father_address = user.user_profile.local_address
                    user.user_profile.is_father_address_same_as_local = True
                    user.user_profile.save()
                    location = user.user_profile.father_address
                    serializer = LocationSerializer(location, data=data)
                    serializer.is_valid(raise_exception=True)
                    result = serializer.data
                    result[
                        "is_permenant_address_same_as_local"
                    ] = user.user_profile.is_permenant_address_same_as_local
                    result[
                        "is_father_address_same_as_local"
                    ] = user.user_profile.is_father_address_same_as_local
                    return Response(
                        result,
                    )
            else:
                location = user.user_profile.father_address
                serializer = LocationSerializer(location, data=data)

        serializer.is_valid(raise_exception=True)
        serializer.update(instance=location, validated_data=data)
        serializer.is_valid(raise_exception=True)
        result = serializer.data
        result[
            "is_permenant_address_same_as_local"
        ] = user.user_profile.is_permenant_address_same_as_local
        result[
            "is_father_address_same_as_local"
        ] = user.user_profile.is_father_address_same_as_local
        return Response(
            result,
        )


class ApplicantAddressCreateView(APIView):
    def post(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        address_type = self.request.GET["address_type"]
        if "is_permenant_address_same_as_local" in self.request.GET:
            is_permenant_address_same_as_local = self.request.GET[
                "is_permenant_address_same_as_local"
            ]
            if (
                address_type == "permanent_address"
                and is_permenant_address_same_as_local is True
                or is_permenant_address_same_as_local == "true"
            ):
                permanent_address = user.user_profile.local_address
                user.user_profile.permanent_address = permanent_address
                user.user_profile.is_permenant_address_same_as_local = True
                user.user_profile.save()
                serializer = LocationSerializer(permanent_address)
                result = serializer.data
                result[
                    "is_permenant_address_same_as_local"
                ] = user.user_profile.is_permenant_address_same_as_local
                result[
                    "is_father_address_same_as_local"
                ] = user.user_profile.is_father_address_same_as_local
                return Response(
                    result,
                )
        elif "is_father_address_same_as_local" in self.request.GET:
            is_father_address_same_as_local = self.request.GET[
                "is_father_address_same_as_local"
            ]
            if (
                address_type == "father_address"
                and is_father_address_same_as_local is True
                or is_father_address_same_as_local == "true"
            ):
                father_address = user.user_profile.local_address
                user.user_profile.father_address = father_address
                user.user_profile.is_father_address_same_as_local = True
                user.user_profile.save()
                serializer = LocationSerializer(father_address)
                result = serializer.data
                result[
                    "is_permenant_address_same_as_local"
                ] = user.user_profile.is_permenant_address_same_as_local
                result[
                    "is_father_address_same_as_local"
                ] = user.user_profile.is_father_address_same_as_local
                return Response(
                    result,
                )
        else:
            data = self.request.data
            serializer = LocationSerializer(data=data)
            serializer.is_valid(raise_exception=True)
            result = serializer.save(validated_data=data)
            location = Location.objects.get(id=result)
            if address_type == "local_address":
                if user.user_profile.local_address:
                    Location.objects.get(id=result).delete()
                    return Response(
                        data={"messege": "Local Address for Given User Already Exist"},
                    )
                else:
                    user.user_profile.local_address = location
                    user.user_profile.save()
            elif address_type == "permanent_address":
                if user.user_profile.permanent_address:
                    Location.objects.get(id=result).delete()
                    return Response(
                        data={
                            "messege": "Permanent Address for Given User Already Exist"
                        }
                    )
                else:
                    user.user_profile.permanent_address = location
                    user.user_profile.save()
            else:
                if user.user_profile.father_address:
                    Location.objects.get(id=result).delete()
                    return Response(
                        data={"messege": "Father Address for Given User Already Exist"}
                    )
                else:
                    user.user_profile.father_address = location
                    user.user_profile.save()

            serializer = LocationSerializer(location)
            # serializer.is_valid(raise_exception=True)
            result = serializer.data
            result[
                "is_permenant_address_same_as_local"
            ] = user.user_profile.is_permenant_address_same_as_local
            result[
                "is_father_address_same_as_local"
            ] = user.user_profile.is_father_address_same_as_local
            return Response(result)


class ApplicantQualificationsListView(APIView):
    def get(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        try:
            if user.user_profile.education_details.filter(is_deleted=False).count() > 0:
                qualifications = user.user_profile.education_details.filter(
                    is_deleted=False
                )
                serializer = UserEducationDetailsSerializer(qualifications, many=True)
                return Response(serializer.data)
            else:
                return Response(
                    data={
                        "messege": "User Qualifications not found",
                        "isEmpty": "true",
                    },
                )
        except:
            return Response(
                data={"messege": "User Qualifications not found", "isEmpty": "true"},
            )


class ApplicantQualificationUpdateView(APIView):
    def put(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        data = self.request.data
        user = User.objects.get(user_id=id)
        qualifications = user.user_profile.education_details.filter(is_deleted=False)
        for qualification_data in data:
            qualification = user.user_profile.education_details.get(
                id=qualification_data["id"]
            )
            serializer = UserEducationDetailsSerializer(
                qualification, data=qualification_data
            )
            serializer.is_valid(raise_exception=True)
            serializer.update(instance=qualification, validated_data=qualification_data)
        serializer = UserEducationDetailsSerializer(qualifications, many=True)
        return Response(serializer.data)


class ApplicantQualificationCreateView(APIView):
    def post(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        data = self.request.data
        user = User.objects.get(user_id=id)
        for qualification_data in data:
            serializer = UserEducationDetailsSerializer(data=qualification_data)
            serializer.is_valid(raise_exception=True)
            result = serializer.save(validated_data=qualification_data)
            qualification = UserEducationDetails.objects.get(id=result)
            user.user_profile.education_details.add(qualification)
            user.user_profile.save()
        qualifications = user.user_profile.education_details.filter(is_deleted=False)
        serializer = UserEducationDetailsSerializer(qualifications, many=True)
        return Response(serializer.data)


class ApplicantQualificationDeleteView(APIView):
    def delete(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        data = request.data
        try:
            education = user.user_profile.education_details.get(id=data["id"])
            education.is_deleted = True
            education.save()
            return Response(
                data={"message": "Record Deleted Successfully."},
            )
        except:
            return Response(
                data={"message": "Details Not Found."},
                status=status.HTTP_401_UNAUTHORIZED,
            )


class ApplicantExperiencesListView(APIView):
    def get(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        try:
            if not user.user_profile.is_fresher:
                if user.user_profile.experiences.filter(is_deleted=False).count() > 0:
                    experiences = user.user_profile.experiences.filter(is_deleted=False)
                    serializer = UserExperienceDetailsSerializer(experiences, many=True)
                    return Response(serializer.data)
                else:
                    return Response(
                        data={
                            "message": "User Experiences not found",
                            "isEmpty": "true",
                        },
                    )
            else:
                experiences = user.user_profile.experiences.filter(is_deleted=False)
                for experience_data in experiences:
                    experience = user.user_profile.experiences.update(is_deleted=True)
                    experience.is_deleted = True
                    experience.save()
                return Response(
                    data={
                        "message": "User is not an Experienced Candidate.",
                        "isEmpty": "true",
                    }
                )
        except:
            return Response(
                data={"message": "User Experiences not found", "isEmpty": "true"},
            )


class ApplicantExperienceUpdateView(APIView):
    def put(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        data = self.request.data
        user = User.objects.get(user_id=id)
        experiences = user.user_profile.experiences.filter(is_deleted=False)
        for experience_data in data:
            experience = user.user_profile.experiences.get(id=experience_data["id"])
            serializer = UserExperienceDetailsSerializer(
                experience, data=experience_data
            )
            serializer.is_valid(raise_exception=True)
            serializer.update(instance=experience, validated_data=experience_data)
        serializer = UserExperienceDetailsSerializer(experiences, many=True)
        return Response(serializer.data)


class ApplicantExperienceCreateView(APIView):
    def post(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        data = self.request.data
        user = User.objects.get(user_id=id)
        for experience_data in data:
            serializer = UserExperienceDetailsSerializer(data=experience_data)
            serializer.is_valid(raise_exception=True)
            result = serializer.save(validated_data=experience_data)
            experience = UserExperienceDetails.objects.get(id=result)
            user.user_profile.experiences.add(experience)
            user.user_profile.save()
        experiences = user.user_profile.experiences.filter(is_deleted=False)
        serializer = UserExperienceDetailsSerializer(experiences, many=True)
        return Response(serializer.data)


class ApplicantExperienceDeleteView(APIView):
    def delete(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        data = request.data
        try:
            experience = user.user_profile.experiences.get(id=data["id"])
            experience.is_deleted = True
            experience.save()
            return Response(
                data={"message": "Record Deleted Successfully."},
            )
        except:
            return Response(
                data={"message": "Details Not Found."},
                status=status.HTTP_401_UNAUTHORIZED,
            )


class NeeriRelationsListView(APIView):
    def get(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        try:
            if user.user_profile.neeri_relation.filter(is_deleted=False).count() > 0:
                neeri_relations = user.user_profile.neeri_relation.filter(
                    is_deleted=False
                )
                serializer = NeeriRelationSerializer(neeri_relations, many=True)
                return Response(serializer.data)
            else:
                return Response(
                    data={"messege": "Neeri Relations not found", "isEmpty": "true"},
                )
        except:
            return Response(
                data={"messege": "Neeri Relations not found", "isEmpty": "true"},
            )


class NeeriRelationUpdateView(APIView):
    def put(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        data = self.request.data
        user = User.objects.get(user_id=id)
        neeri_relations = user.user_profile.neeri_relation.filter(is_deleted=False)
        for relation_data in data:
            relation = user.user_profile.neeri_relation.get(id=relation_data["id"])
            serializer = NeeriRelationSerializer(relation, data=relation_data)
            serializer.is_valid(raise_exception=True)
            serializer.update(instance=relation, validated_data=relation_data)
        serializer = NeeriRelationSerializer(neeri_relations, many=True)
        return Response(serializer.data)


class NeeriRelationCreateView(APIView):
    def post(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        data = self.request.data
        user = User.objects.get(user_id=id)
        for relation_data in data:
            serializer = NeeriRelationSerializer(data=relation_data)
            serializer.is_valid(raise_exception=True)
            result = serializer.save(validated_data=relation_data)
            relation = NeeriRelation.objects.get(id=result)
            user.user_profile.neeri_relation.add(relation)
            user.user_profile.save()
        experiences = user.user_profile.neeri_relation.filter(is_deleted=False)
        serializer = NeeriRelationSerializer(experiences, many=True)
        return Response(serializer.data)


class NeeriRelationDeleteView(APIView):
    def delete(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        data = request.data
        try:
            neeri_relation = user.user_profile.neeri_relation.get(id=data["id"])
            neeri_relation.is_deleted = True
            neeri_relation.save()
            return Response(
                data={"message": "Record Deleted Successfully."},
            )
        except:
            return Response(
                data={"message": "Details Not Found."},
                status=status.HTTP_401_UNAUTHORIZED,
            )


class OverseasVisitsListView(APIView):
    def get(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        try:
            if user.user_profile.overseas_visits.filter(is_deleted=False).count() > 0:
                visits = user.user_profile.overseas_visits.filter(is_deleted=False)
                serializer = OverseasVisitsSerializer(visits, many=True)
                return Response(serializer.data)
            else:
                return Response(
                    data={"messege": "Overseas Visits not found", "isEmpty": "true"},
                )
        except:
            return Response(
                data={"messege": "Overseas Visits not found", "isEmpty": "true"},
            )


class OverseasVisitsCreateView(APIView):
    def post(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        data = self.request.data
        user = User.objects.get(user_id=id)
        for visits_data in data:
            serializer = OverseasVisitsSerializer(data=visits_data)
            serializer.is_valid(raise_exception=True)
            result = serializer.save(validated_data=visits_data)
            visit = OverseasVisits.objects.get(id=result)
            user.user_profile.overseas_visits.add(visit)
            user.user_profile.save()
        visits = user.user_profile.overseas_visits.filter(is_deleted=False)
        serializer = OverseasVisitsSerializer(visits, many=True)
        return Response(serializer.data)


class OverseasVisitsUpdateView(APIView):
    def put(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        data = self.request.data
        user = User.objects.get(user_id=id)
        visits = user.user_profile.overseas_visits.filter(is_deleted=False)
        for visits_data in data:
            visit = user.user_profile.overseas_visits.get(id=visits_data["id"])
            serializer = OverseasVisitsSerializer(visit, data=visits_data)
            serializer.is_valid(raise_exception=True)
            serializer.update(instance=visit, validated_data=visits_data)
        serializer = OverseasVisitsSerializer(visits, many=True)
        return Response(serializer.data)


class OverseasVisitsDeleteView(APIView):
    def delete(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        data = request.data
        try:
            overseas_visit = user.user_profile.overseas_visits.get(id=data["id"])
            overseas_visit.is_deleted = True
            overseas_visit.save()
            return Response(
                data={"message": "Record Deleted Successfully."},
            )
        except:
            return Response(
                data={"message": "Details Not Found."},
                status=status.HTTP_401_UNAUTHORIZED,
            )


class ApplicantReferencesListView(APIView):
    def get(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        try:
            if user.user_profile.references.filter(is_deleted=False).count() > 0:
                references = user.user_profile.references.filter(is_deleted=False)
                serializer = ReferencesSerializer(references, many=True)
                return Response(serializer.data)
            else:
                return Response(
                    data={"messege": "References not found", "isEmpty": "true"},
                )
        except:
            return Response(
                data={"messege": "References not found", "isEmpty": "true"},
            )


class ApplicantReferencesCreateView(APIView):
    def post(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        data = self.request.data
        user = User.objects.get(user_id=id)
        for reference_data in data:
            serializer = ReferencesSerializer(data=reference_data)
            serializer.is_valid(raise_exception=True)
            result = serializer.save(validated_data=reference_data)
            reference = UserReference.objects.get(id=result)
            user.user_profile.references.add(reference)
            user.user_profile.save()
        references = user.user_profile.references.filter(is_deleted=False)
        serializer = ReferencesSerializer(references, many=True)
        return Response(serializer.data)


class ApplicantReferencesUpdateView(APIView):
    def put(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        data = self.request.data
        user = User.objects.get(user_id=id)
        references = user.user_profile.references.filter(is_deleted=False)
        for reference_data in data:
            reference = user.user_profile.references.get(id=reference_data["id"])
            serializer = ReferencesSerializer(reference, data=reference_data)
            serializer.is_valid(raise_exception=True)
            serializer.update(instance=reference, validated_data=reference_data)
        serializer = ReferencesSerializer(references, many=True)
        return Response(serializer.data)


class ApplicantReferencesDeleteView(APIView):
    def delete(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        data = request.data
        try:
            reference = user.user_profile.references.get(id=data["id"])
            reference.is_deleted = True
            reference.save()
            return Response(
                data={"message": "Record Deleted Successfully."},
            )
        except:
            return Response(
                data={"message": "Details Not Found."},
                status=status.HTTP_401_UNAUTHORIZED,
            )


class ApplicantLanguagesListView(APIView):
    def get(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        try:
            if user.user_profile.languages.filter(is_deleted=False).count() > 0:
                languages = user.user_profile.languages.filter(is_deleted=False)
                serializer = LanguagesSerializer(languages, many=True)
                return Response(serializer.data)
            else:
                return Response(
                    data={"messege": "Languages not found", "isEmpty": "true"},
                )
        except:
            return Response(
                data={"messege": "Languages not found", "isEmpty": "true"},
            )


class ApplicantLanguagesCreateView(APIView):
    def post(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        data = self.request.data
        user = User.objects.get(user_id=id)
        for language_data in data:
            serializer = LanguagesSerializer(data=language_data)
            serializer.is_valid(raise_exception=True)
            result = serializer.save(validated_data=language_data)
            language = UserLanguages.objects.get(id=result)
            user.user_profile.languages.add(language)
            user.user_profile.save()
        languages = user.user_profile.languages.filter(is_deleted=False)
        serializer = LanguagesSerializer(languages, many=True)
        return Response(serializer.data)


class ApplicantLanguagesUpdateView(APIView):
    def put(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        data = self.request.data
        user = User.objects.get(user_id=id)
        languages = user.user_profile.languages.filter(is_deleted=False)
        for language_data in data:
            language = user.user_profile.languages.get(id=language_data["id"])
            serializer = LanguagesSerializer(language, data=language_data)
            serializer.is_valid(raise_exception=True)
            serializer.update(instance=language, validated_data=language_data)
        serializer = LanguagesSerializer(languages, many=True)
        return Response(serializer.data)


class ApplicantLanguagesDeleteView(APIView):
    def delete(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        data = request.data
        try:
            language = user.user_profile.languages.get(id=data["id"])
            language.is_deleted = True
            language.save()
            return Response(
                data={"message": "Record Deleted Successfully."},
            )
        except:
            return Response(
                data={"message": "Details Not Found."},
                status=status.HTTP_401_UNAUTHORIZED,
            )


class PublishedPapersListView(APIView):
    def get(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        try:
            if user.user_profile.published_papers.filter(is_deleted=False).count() > 0:
                papers = user.user_profile.published_papers.filter(is_deleted=False)
                serializer = PublishedPapersSerializer(papers, many=True)
                return Response(serializer.data)
            else:
                return Response(
                    data={"messege": "Published Papers not found", "isEmpty": "true"},
                )
        except:
            return Response(
                data={"messege": "Published Papers not found", "isEmpty": "true"},
            )


class PublishedPapersCreateView(APIView):
    def post(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        data = self.request.data
        user = User.objects.get(user_id=id)
        for paper_data in data:
            temp_paper_data = paper_data
            temp_paper_data["user_id"] = id
            serializer = PublishedPapersSerializer(data=temp_paper_data)
            serializer.is_valid(raise_exception=True)
            result = serializer.save(validated_data=temp_paper_data)
            paper = PublishedPapers.objects.get(id=result)
            user.user_profile.published_papers.add(paper)
            user.user_profile.save()
        papers = user.user_profile.published_papers.filter(is_deleted=False)
        serializer = PublishedPapersSerializer(papers, many=True)
        return Response(serializer.data)


class PublishedPapersUpdateView(APIView):
    def put(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        data = self.request.data
        user = User.objects.get(user_id=id)
        for paper_data in data:
            paper = user.user_profile.published_papers.get(id=paper_data["id"])
            serializer = PublishedPapersSerializer(paper, data=paper_data)
            serializer.is_valid(raise_exception=True)
            serializer.update(instance=paper, validated_data=paper_data)
        papers = user.user_profile.published_papers.filter(is_deleted=False)
        response_data = PublishedPapersSerializer(papers, many=True)
        return Response(response_data.data)


class PublishedPapersDeleteView(APIView):
    def delete(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        data = request.data
        try:
            paper = user.user_profile.published_papers.get(id=data["id"])
            paper.is_deleted = True
            paper.save()
            return Response(
                data={"message": "Record Deleted Successfully."},
            )
        except:
            return Response(
                data={"message": "Details Not Found."},
                status=status.HTTP_401_UNAUTHORIZED,
            )


# Todo:
# class ApplicantAppliedJobSearchListView(ListAPIView):
#     queryset = UserJobPositions.objects.all()
#     serializer_class = ApplicantJobPositionsSerializer
#     filter_backends = [SearchFilter]
#     search_fields = ('notification_id', 'description', 'hiring_status')
#


class ApplicantAppliedJobListView(APIView):
    def get(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        if UserJobPositions.objects.filter(user=user, is_deleted=False).count() > 0:
            user_job_positions = UserJobPositions.objects.filter(
                user=user, is_deleted=False
            )
            serializer = ApplicantJobPositionsSerializer(user_job_positions, many=True)
            return Response(serializer.data)
        else:
            return Response(
                data={"messege": "Applied job list not found", "isEmpty": "true"},
            )


class ApplicantAppliedJobDetailView(APIView):
    def get(self, request, *args, **kwargs):
        user = request.user
        application = UserJobPositions.objects.get(id=self.kwargs["id"])
        if application.user != user:
            return Response(
                data={"success": False, "error": "Permission denied"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        position = PositionQualificationMappingSerializer(application.position)
        return Response(data=position.data)


class JobApplyCheckoutView(APIView):
    def post(self, request, *args, **kwargs):
        try:
            data = request.data
            job_posting = JobPosting.objects.get(job_posting_id=self.kwargs["id"])
            positions = PositionQualificationMapping.objects.filter(
                id__in=data["positions"]
            )
            applications = []
            user = request.user
            if job_posting.job_type == JobPosting.Contract_Basis:
                if user.subscription.filter(user=user, expired=False).exists():
                    for position in positions:
                        application = UserJobPositions.objects.create(
                            user=user,
                            position=position,
                            job_posting=job_posting,
                            applied_job_status=UserJobPositions.DOCUMENT_PENDING,
                        )
                        applications.append(application.id)
                    return Response(
                        data={
                            "success": True,
                            "message": "Job application successful",
                            "applications": applications,
                        }
                    )
                subscription_fee = FeeMaster.objects.get(
                    category=JobPosting.Contract_Basis
                ).fee * len(positions)
                return Response(
                    data={
                        "success": False,
                        "message": "User subscription expired",
                        "fee": subscription_fee,
                    }
                )
            else:
                user_profile = user.user_profile
                relaxation_rule = user_profile.relaxation_rule
                for position in positions:
                    if not (
                        position.min_age
                        < user_profile.age
                        - ((relaxation_rule and relaxation_rule.age_relaxation) or 0)
                        < position.max_age
                    ):
                        return Response(
                            data={
                                "success": False,
                                "message": f"Age eligibility not fulfilled for {position.position_display_name}",
                            }
                        )
                fee = FeeMaster.objects.get(category=JobPosting.Permanent).fee - (
                    (relaxation_rule and relaxation_rule.fee_relaxation) or 0
                ) * len(positions)
                if fee == 0:
                    for position in positions:
                        application = UserJobPositions.objects.create(
                            user=user,
                            position=position,
                            job_posting=job_posting,
                            applied_job_status=UserJobPositions.DOCUMENT_PENDING,
                        )
                        applications.append(application.id)
                    return Response(
                        data={
                            "success": True,
                            "message": "Job application successful",
                            "applications": applications,
                        }
                    )
                return Response(data={"success": True, "fee": fee})
        except Exception as e:
            return Response(data={"success": False, "message": str(e)})


class ApplicationDocumentUpdateView(APIView):
    def get(self, request, *args, **kwargs):
        applied_positions = []
        applications = UserJobPositions.objects.select_related("position").filter(
            applied_job_status=UserJobPositions.DOCUMENT_PENDING,
            user=request.user,
            documents__isnull=True,
        )
        for application in applications:
            position = PositionQualificationMappingSerializer(application.position)
            applied_positions.append(position.data)
        return Response(data=applied_positions)

    def post(self, request, *args, **kwargs):
        data = self.request.data
        application = UserJobPositions.objects.get(id=data["application_id"])
        documents = UserDocuments.objects.filter(doc_id__in=data["documents"])
        if len(data["documents"]) != len(documents):
            return Response(
                data={"success": False, "error": "Invalid document ids"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        application.documents.add(*documents)
        application.applied_job_status = UserJobPositions.RECEIVED
        application.save()
        return Response(data={"success": True})


# While creating new entry of UserJobPositions set closing_date to a closing_date og JobPosting


class ApplicantProfilePercentageView(APIView):
    def get(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        try:
            percentage = user.user_profile.profile_percentage
            return Response(data={"percentage": percentage})
        except:
            return Response(
                data={"messsege": "User-Profile not found", "percentage": "0"},
            )


class ProfessionalTrainingListView(APIView):
    def get(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        try:
            if (
                user.user_profile.professional_trainings.filter(
                    is_deleted=False
                ).count()
                > 0
            ):
                professional_trainings = (
                    user.user_profile.professional_trainings.filter(is_deleted=False)
                )
                serializer = ProfessionalTrainingSerializer(
                    professional_trainings, many=True
                )
                return Response(serializer.data)
            else:
                return Response(
                    data={
                        "messege": "Professional Trainings not found",
                        "isEmpty": "true",
                    },
                )
        except:
            return Response(
                data={"messege": "Professional Trainings not found", "isEmpty": "true"},
            )


class ProfessionalTrainingUpdateView(APIView):
    def put(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        data = self.request.data
        user = User.objects.get(user_id=id)
        professional_trainings = user.user_profile.professional_trainings.filter(
            is_deleted=False
        )
        for professional_training_data in data:
            professional_training = user.user_profile.professional_trainings.get(
                id=professional_training_data["id"]
            )
            serializer = ProfessionalTrainingSerializer(
                professional_training, data=professional_training_data
            )
            serializer.is_valid(raise_exception=True)
            serializer.update(
                instance=professional_training,
                validated_data=professional_training_data,
            )
        serializer = ProfessionalTrainingSerializer(professional_trainings, many=True)
        return Response(serializer.data)


class ProfessionalTrainingCreateView(APIView):
    def post(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        data = self.request.data
        user = User.objects.get(user_id=id)
        for professional_training_data in data:
            serializer = ProfessionalTrainingSerializer(data=professional_training_data)
            serializer.is_valid(raise_exception=True)
            result = serializer.save(validated_data=professional_training_data)
            professional_training = ProfessionalTraining.objects.get(id=result)
            user.user_profile.professional_trainings.add(professional_training)
            user.user_profile.save()
        professional_trainings = user.user_profile.professional_trainings.filter(
            is_deleted=False
        )
        serializer = ProfessionalTrainingSerializer(professional_trainings, many=True)
        return Response(serializer.data)


class ProfessionalTrainingDeleteView(APIView):
    def delete(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        data = request.data
        try:
            professional_training = user.user_profile.professional_trainings.get(
                id=data["id"]
            )
            professional_training.is_deleted = True
            professional_training.save()
            return Response(
                data={"message": "Record Deleted Successfully(Soft Delete)."},
            )
        except:
            return Response(
                data={"message": "Details Not Found."},
                status=status.HTTP_401_UNAUTHORIZED,
            )


class FileUpload(APIView):
    def post(self, request, *args, **kwargs):
        if "file" not in request.data:
            return Response(
                data={"messege": "No file Found"},
            )

        file = request.data["file"]
        user = request.user
        doc_type = self.request.GET["doc_type"]
        filename, extension = os.path.splitext(file.name)
        timestamp = int(datetime.datetime.now().timestamp())
        filename = f"{filename}_{timestamp}{extension}"
        if doc_type == "profile_photo":
            allowed_extensions = ["jpg", "jpeg", "png"]
            if extension.lower() in allowed_extensions:
                path = f"applicant_documents/{user.user_id}/{filename}"
                default_storage.save(
                    f"{settings.MEDIA_ROOT}/{path}",
                    ContentFile(file.read()),
                )
                temp_path = f"{settings.BASE_URL}{settings.MEDIA_URL}{path}"
                doc = UserDocuments.objects.create(
                    doc_file_path=temp_path, doc_name=filename
                )
                user.user_profile.documents.add(doc)
                user.user_profile.profile_photo = temp_path
                user.user_profile.save()
            else:
                return Response(
                    data={"messege": "Enter file of type jpg,jpeg and png."},
                )

        elif doc_type in ("paper_attachment", "applicant"):
            if doc_type == "paper_attachment":
                path = f"applicant_documents/{user.user_id}/papers/{filename}"
            else:
                path = f"applicant_documents/{user.user_id}/{filename}"
            default_storage.save(
                f"{settings.MEDIA_ROOT}/{path}", ContentFile(file.read())
            )
            temp_path = f"{settings.BASE_URL}{settings.MEDIA_URL}{path}"
            doc = UserDocuments.objects.create(
                doc_file_path=temp_path, doc_name=filename
            )

        elif doc_type == "office_memo":
            job_posting_id = self.request.GET["job_posting_id"]
            job_posting = JobPosting.objects.get(job_posting_id=job_posting_id)
            path = f"job_posting_documents/{job_posting.job_posting_id}/{filename}"
            default_storage.save(
                f"{settings.MEDIA_ROOT}/{path}",
                ContentFile(file.read()),
            )
            temp_path = f"{settings.BASE_URL}{settings.MEDIA_URL}{path}"
            doc = JobDocuments.objects.create(
                doc_file_path=temp_path, doc_name=filename
            )
            job_posting.office_memorandum = doc
            job_posting.save()

        elif doc_type == "job_docs":
            name = self.request.GET["name"]
            path = f"job_posting_documents / {filename}"
            default_storage.save(
                f"{settings.MEDIA_ROOT}/{path}",
                ContentFile(file.read()),
            )
            temp_path = f"{settings.BASE_URL}{settings.MEDIA_URL}{path}"
            doc = JobDocuments.objects.create(doc_file_path=temp_path, doc_name=name)

        return Response(
            data={
                "messege": "File uploaded successfully",
                "doc_file_path": doc.doc_file_path,
                "doc_name": doc.doc_name,
                "doc_id": doc.doc_id,
            }
        )


class OtherInformationDetailView(APIView):
    def get(self, request, *args, **kwargs):
        try:
            id = self.kwargs["id"]
            user = User.objects.get(user_id=id)
            other_info = user.user_profile.other_info
            serializer = OtherInformationSerializer(other_info)
            return Response(serializer.data)
        except:
            return Response(
                data={"messege": "OtherInfo not found", "isEmpty": "true"},
            )


class OtherInformationCreateView(APIView):
    def post(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        data = self.request.data
        user = User.objects.get(user_id=id)
        if user.user_profile.other_info:
            return Response(
                data={"messege": "OtherInformation Already Created"},
            )
        else:
            serializer = OtherInformationSerializer(data=data)
            serializer.is_valid(raise_exception=True)
            result = serializer.save(validated_data=data)
            other_info = OtherInformation.objects.get(id=result)
            user.user_profile.other_info = other_info
            user.user_profile.save()
            serializer = OtherInformationSerializer(other_info)
            return Response(serializer.data)


class OtherInformationUpdateView(APIView):
    def put(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        data = self.request.data
        user = User.objects.get(user_id=id)
        other_info = user.user_profile.other_info
        serializer = OtherInformationSerializer(other_info, data=data)
        serializer.is_valid(raise_exception=True)
        serializer.update(instance=other_info, validated_data=data)
        serializer = OtherInformationSerializer(other_info)
        return Response(serializer.data)


class OtherInformationDeleteView(APIView):
    def delete(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        user = User.objects.get(user_id=id)
        data = request.data
        try:
            othet_info = user.user_profile.other_info
            othet_info.is_deleted = True
            othet_info.save()
            return Response(
                data={"message": "Record Deleted Successfully(Soft Delete)."},
            )
        except:
            return Response(
                data={"message": "Details Not Found."},
                status=status.HTTP_401_UNAUTHORIZED,
            )


class UserDocumentView(APIView):
    def get(self, request, *args, **kwargs):
        user = User.objects.get(user_id=self.kwargs["id"])
        if not hasattr(user, "user_profile"):
            return Response(
                data={"message": "User Profile does not exist"},
                status=status.HTTP_404_NOT_FOUND,
            )
        documents = user.user_profile.documents.all()
        serializer = UserDocumentsSerializer(documents, many=True)
        return Response(serializer.data)

    @atomic
    def post(self, request, *args, **kwargs):
        user = User.objects.get(user_id=self.kwargs["id"])
        if not hasattr(user, "user_profile"):
            return Response(
                data={"message": "User Profile does not exist"},
                status=status.HTTP_404_NOT_FOUND,
            )

        data = request.data
        try:
            user_profile = user.user_profile
            user_profile.documents.clear()
            for doc_info in data:
                user_document = UserDocuments.objects.get(doc_id=doc_info["doc_id"])
                user_document.doc_name = doc_info["doc_name"]
                user_document.save()
                user_profile.documents.add(user_document)
            return Response(
                data={"message": "Documents added successfully"},
            )
        except Exception as e:
            return Response(
                data={"message": f"Error adding documents ({str(e)})"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class ProfileDetailView(RetrieveAPIView):
    queryset = UserProfile.objects.select_related("user")
    serializer_class = UserProfilePreviewSerializer
    lookup_field = "user__user_id"
    lookup_url_kwarg = "id"


class ApplicantListView(APIView):
    def get(self, request, *args, **kwargs):
        applicants = User.objects.filter(is_deleted=False)
        UserRoles.objects.filter(user=applicants)
        serializer = CustomUserSerializer(applicants, many=True)
        return Response(serializer.data)


class CompareApplicantListView(APIView):
    def get(self, request, *args, **kwargs):
        try:
            user_id = self.kwargs["id"]
            applicants = UserProfile.objects.filter(
                user__user_id=user_id, is_deleted=False
            )
            serializer = CompareApplicantSerializer(applicants, many=True)
            return Response(serializer.data)
        except:
            if UserProfile.objects.filter(is_deleted=False).count() > 0:
                applicants = UserProfile.objects.filter(is_deleted=False)
                serializer = CompareApplicantSerializer(applicants, many=True)
                return Response(serializer.data)
            else:
                return Response(
                    data={"message": "No Records found"},
                    status=status.HTTP_404_NOT_FOUND,
                )


class MentorMasterListView(APIView):
    def get(self, request, *args, **kwargs):
        try:
            mentor_id = self.kwargs["id"]
            if MentorMaster.objects.filter(
                mentor_id=mentor_id, is_deleted=False
            ).exists():
                mentor = MentorMaster.objects.get(mentor_id=mentor_id, is_deleted=False)
                serializer = MentorMasterSerializer(mentor)
                return Response(serializer.data)
            else:
                return Response(
                    data={"message": "Details Not Found."},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
        except:
            mentor = MentorMaster.objects.filter(is_deleted=False)
            serializer = MentorMasterSerializer(mentor, many=True)
            return Response(serializer.data)

    # def post(self, request, *args, **kwargs):
    #     data = self.request.data
    #     serializer = MentorMasterSerializer(data=data)
    #     serializer.is_valid(raise_exception=True)
    #     serializer.save()
    #     return Response(serializer.data)

    def delete(self, request, *args, **kwargs):
        try:
            id = self.kwargs["id"]
            mentor = MentorMaster.objects.get(mentor_id=id)
            # print("mentor.mentor_id---------->",mentor.mentor_id)
            # print("mentor---------->",mentor)
            # if Trainee.objects.filter(mentor=mentor).exists():
            #     trainee = Trainee.objects.get(mentor=mentor)
            #     for t in trainee:
            #         t.is_deleted = True
            #         t.save()
            #     print("trainee---------->", trainee)

            mentor.is_deleted = True
            mentor.save()
            return Response(
                data={"message": "Mentor Deleted Successfully(Soft Delete)."},
            )
        except:
            return Response(
                data={"message": "Mentor Not Found."},
                status=status.HTTP_401_UNAUTHORIZED,
            )


class TraineeSearchListView(ListAPIView):
    queryset = Trainee.objects.all()
    serializer_class = TraineeSerializer
    filterset_fields = [
        "trainee_name",
        "division__division_name",
        "mentor__mentor_name",
        "emp_start_date",
        "emp_end_date",
    ]


class TraineeListView(APIView):
    def get(self, request, *args, **kwargs):
        try:
            trainee_id = self.kwargs["id"]
            if Trainee.objects.filter(trainee_id=trainee_id, is_deleted=False).exists():
                trainee = Trainee.objects.get(trainee_id=trainee_id, is_deleted=False)
                serializer = TraineeSerializer(trainee)
                return Response(serializer.data)
            else:
                return Response(
                    data={"message": "Details Not Found."},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
        except:
            trainee = Trainee.objects.filter(is_deleted=False)
            serializer = TraineeSerializer(trainee, many=True)
            return Response(serializer.data)

    def delete(self, request, *args, **kwargs):
        try:
            id = self.kwargs["id"]
            trainee = Trainee.objects.get(trainee_id=id)
            trainee.is_deleted = True
            trainee.save()
            return Response(
                data={"message": "Trainee Deleted Successfully(Soft Delete)."},
            )
        except:
            return Response(
                data={"message": "Trainee Not Found."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

    def post(self, request, *args, **kwargs):
        data = self.request.data
        serializer = TraineeSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        result = serializer.save(validated_data=data)
        if result:
            trainee = Trainee.objects.get(trainee_id=result)
            serializer = TraineeSerializer(trainee)
            return Response(serializer.data)
        else:
            return Response(
                data={
                    "message": "This Mentor already added to 4 Trainee, try with another mentor."
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

    def put(self, request, *args, **kwargs):
        data = self.request.data
        id = self.kwargs["id"]
        trainee = Trainee.objects.get(trainee_id=id, is_deleted=False)
        serializer = TraineeSerializer(trainee, data=data)
        serializer.is_valid(raise_exception=True)
        result = serializer.update(instance=trainee, validated_data=data)
        if result:
            trainee = Trainee.objects.get(trainee_id=result)
            serializer = TraineeSerializer(trainee)
            return Response(serializer.data)
        else:
            return Response(
                data={
                    "message": "This Mentor already added to 4 Trainee, try with another mentor."
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )


class RelaxationMasterListView(APIView):
    def get(self, request, *args, **kwargs):
        try:
            relaxation_rule_id = self.kwargs["id"]
            if RelaxationMaster.objects.filter(
                relaxation_rule_id=relaxation_rule_id, is_deleted=False
            ).exists():
                relax = RelaxationMaster.objects.get(
                    relaxation_rule_id=relaxation_rule_id, is_deleted=False
                )
                serializer = RelaxationMasterSerializer(relax)
                return Response(serializer.data)
            else:
                return Response(
                    data={"message": "Details Not Found."},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
        except:
            relax = RelaxationMaster.objects.filter(is_deleted=False)
            serializer = RelaxationMasterSerializer(relax, many=True)
            return Response(serializer.data)

    def delete(self, request, *args, **kwargs):
        try:
            id = self.kwargs["id"]
            relax = RelaxationMaster.objects.get(relaxation_rule_id=id)
            relax.is_deleted = True
            relax.save()
            return Response(
                data={"message": "Relaxation Deleted Successfully(Soft Delete)."}
            )
        except:
            return Response(
                data={"message": "Details Not Found."},
                status=status.HTTP_401_UNAUTHORIZED,
            )


class RelaxationCategoryMasterListView(APIView):
    def get(self, request, *args, **kwargs):
        try:
            mentor_id = self.kwargs["id"]
            if RelaxationCategoryMaster.objects.filter(
                relaxation_cat_id=mentor_id, is_deleted=False
            ).exists():
                relax = RelaxationCategoryMaster.objects.get(
                    relaxation_cat_id=mentor_id, is_deleted=False
                )
                serializer = RelaxationCategoryMasterSerializer(relax)
                return Response(serializer.data)
            else:
                return Response(
                    data={"message": "Details Not Found."},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
        except:
            relax = RelaxationCategoryMaster.objects.filter(is_deleted=False)
            serializer = RelaxationCategoryMasterSerializer(relax, many=True)
            return Response(serializer.data)

    def delete(self, request, *args, **kwargs):
        try:
            id = self.kwargs["id"]
            relax_cat = RelaxationCategoryMaster.objects.get(relaxation_cat_id=id)
            relax_cat.is_deleted = True
            relax_cat.save()
            return Response(
                data={
                    "message": "Relaxation Category Deleted Successfully(Soft Delete)."
                }
            )
        except:
            return Response(
                data={"message": "Details Not Found."},
                status=status.HTTP_401_UNAUTHORIZED,
            )
