import datetime
import random
import uuid

from django.contrib import auth
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models

from neeri_recruitment_portal.settings import OTP_EXPIRY_TIME, ACCOUNT_LOCKED_TIME
from neeri_recruitment_portal.validators import EmailValidator


class BaseModel(models.Model):
    created_by = models.CharField(
        max_length=50, null=True, blank=True, help_text="username"
    )
    updated_by = models.CharField(
        max_length=25, null=True, blank=True, help_text="username"
    )
    created_at = models.DateTimeField(null=True, blank=True, auto_now_add=True)
    updated_at = models.DateTimeField(null=True, blank=True)
    is_deleted = models.BooleanField(default=False, help_text="Used for Soft Delete")

    class Meta:
        abstract = True


class CustomUserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, mobile_no, email, password, **extra_fields):
        """
        Create and save a user with the given mobile_no, email, and password.
        """
        if not email:
            raise ValueError("The given email must be set")
        email = self.normalize_email(email)
        user = self.model(mobile_no=mobile_no, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, mobile_no, email=None, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(mobile_no, email, password, **extra_fields)

    def create_superuser(self, mobile_no, email=None, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self._create_user(mobile_no, email, password, **extra_fields)

    def with_perm(
        self, perm, is_active=True, include_superusers=True, backend=None, obj=None
    ):
        if backend is None:
            backends = auth._get_backends(return_tuples=True)
            if len(backends) == 1:
                backend, _ = backends[0]
            else:
                raise ValueError(
                    "You have multiple authentication backends configured and "
                    "therefore must provide the `backend` argument."
                )
        elif not isinstance(backend, str):
            raise TypeError(
                "backend must be a dotted import path string (got %r)." % backend
            )
        else:
            backend = auth.load_backend(backend)
        if hasattr(backend, "with_perm"):
            return backend.with_perm(
                perm,
                is_active=is_active,
                include_superusers=include_superusers,
                obj=obj,
            )
        return self.none()


class User(AbstractUser, BaseModel):
    REQUIRED_FIELDS = ["mobile_no"]
    user_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # Limiting the username input to accept only digits, ".", "-" and "_"
    username = models.CharField(max_length=30, blank=True, null=True)
    # models.CharField(
    #     _("username"),
    #     max_length=25,
    #     help_text=_(
    #         "Required. Between 5 and 25 characters. "
    #         "May only contain letters, digits, - (hyphen) and _ (underscore)."
    #     ),
    #     validators=[
    #         UsernameValidator(),
    #         MinLengthValidator(5, "Minimum 5 characters."),
    #     ],
    #     blank=True,
    #     unique=True
    # )
    mobile_no = models.CharField(max_length=10, unique=True, null=True)
    email = models.EmailField(unique=True, validators=[EmailValidator()])
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    middle_name = models.CharField(max_length=30, blank=True, null=True)
    USERNAME_FIELD = "email"

    class Meta:
        verbose_name = "user"
        verbose_name_plural = "users"

    # def __str__(self):
    #     return self.username

    objects = CustomUserManager()

    def get_email(self):
        email_field_name = self.get_email_field_name()
        return getattr(self, email_field_name, None)

    def set_email(self, new_mail):
        email_field_name = self.get_email_field_name()
        return setattr(self, email_field_name, new_mail)

    def get_full_name(self):
        return " ".join(
            name for name in [self.first_name, self.middle_name, self.last_name] if name
        )


class UserProfile(BaseModel):
    GENDER_MALE = "male"
    GENDER_FEMALE = "female"

    GENDER_CHOICES = [
        (GENDER_MALE, "Male"),
        (GENDER_FEMALE, "Female"),
    ]

    NOT_DECIDED = "not_decided"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    ON_HOLD = "on_hold"
    OTHER = "other"

    STATUS_CHOICES = [
        (NOT_DECIDED, "Not Decided"),
        (ACCEPTED, "Accepted"),
        (REJECTED, "Rejected"),
        (ON_HOLD, "On Hold"),
        (OTHER, "Other"),
    ]

    SC = "sc"
    ST = "st"
    OBC = "obc"
    GEN = "gen"
    PWD = "pwd"

    CASTE_CHOICES = [
        (SC, "SC"),
        (ST, "ST"),
        (OBC, "OBC"),
        (GEN, "GEN"),
        (PWD, "PWD"),
    ]

    user = models.OneToOneField(
        "User", on_delete=models.CASCADE, related_name="user_profile"
    )
    gender = models.CharField(
        null=True, blank=True, choices=GENDER_CHOICES, max_length=20
    )
    # mobile_no = models.CharField(max_length=20, null=True, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    status = models.CharField(
        null=True,
        blank=True,
        choices=STATUS_CHOICES,
        default=NOT_DECIDED,
        max_length=20,
    )
    local_address = models.OneToOneField(
        "user.Location",
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name="local_address",
    )
    permanent_address = models.OneToOneField(
        "user.Location",
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name="permanent_address",
    )
    is_permenant_address_same_as_local = models.BooleanField(default=False)
    is_father_address_same_as_local = models.BooleanField(default=False)
    date_of_birth_in_words = models.CharField(max_length=50, null=True, blank=True)
    place_of_birth = models.CharField(max_length=30, null=True, blank=True)
    father_name = models.CharField(max_length=50, null=True, blank=True)
    father_address = models.OneToOneField(
        "user.Location",
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name="father_address",
    )
    father_occupation = models.CharField(max_length=30, null=True, blank=True)
    religion = models.CharField(max_length=30, null=True, blank=True)
    caste = models.CharField(
        max_length=30, choices=CASTE_CHOICES, null=True, blank=True
    )
    passport_number = models.CharField(max_length=8, null=True, blank=True)
    passport_expiry = models.DateField(null=True, blank=True)
    profile_photo = models.CharField(max_length=200, null=True, blank=True)
    fax_number = models.CharField(max_length=20, null=True, blank=True)
    is_indian_citizen = models.BooleanField(blank=True, null=True, default=True)
    whatsapp_id = models.CharField(max_length=50, null=True, blank=True)
    skype_id = models.CharField(max_length=50, null=True, blank=True)
    # nationality = models.CharField(max_length=50, null=True, blank=True)
    relaxation_rule = models.ForeignKey(
        "user.RelaxationMaster",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="m_relaxation_rules",
    )

    roles = models.ManyToManyField(
        "user.RoleMaster", blank=True, null=True, related_name="user_roles"
    )
    neeri_relation = models.ManyToManyField(
        "NeeriRelation", blank=True, related_name="neeri_relations"
    )
    documents = models.ManyToManyField(
        "user.UserDocuments", blank=True, null=True, related_name="documents"
    )
    education_details = models.ManyToManyField(
        "user.UserEducationDetails",
        blank=True,
        null=True,
        related_name="education_details",
    )
    experiences = models.ManyToManyField(
        "user.UserExperienceDetails", blank=True, null=True, related_name="experiences"
    )
    references = models.ManyToManyField(
        "user.UserReference", blank=True, null=True, related_name="references"
    )
    overseas_visits = models.ManyToManyField(
        "user.OverseasVisits", blank=True, null=True, related_name="overseas_visits"
    )
    languages = models.ManyToManyField(
        "user.UserLanguages", blank=True, null=True, related_name="languages"
    )
    published_papers = models.ManyToManyField(
        "user.PublishedPapers", blank=True, null=True, related_name="published_papers"
    )
    professional_trainings = models.ManyToManyField(
        "user.ProfessionalTraining",
        blank=True,
        null=True,
        related_name="professional_tarinings",
    )
    other_info = models.OneToOneField(
        "user.OtherInformation",
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name="other_info",
    )
    is_fresher = models.BooleanField(blank=True, null=True, default=False)

    @property
    def age(self):
        today = datetime.date.today()
        age = (
            today.year
            - self.date_of_birth.year
            - (
                (today.month, today.day)
                < (self.date_of_birth.month, self.date_of_birth.day)
            )
        )
        return age

    @property
    def profile_percentage(self):

        percent = {
            "gender": 2,
            "is_fresher": 5,
            "date_of_birth": 5,
            "local_address": 5,
            "permanent_address": 5,
            "father_address": 5,
            "date_of_birth_in_words": 2,
            "place_of_birth": 2,
            "father_name": 2,
            "father_occupation": 2,
            "religion": 2,
            "caste": 2,
            "passport_number": 2,
            "passport_expiry": 2,
            "profile_photo": 5,
            "fax_number": 1,
            "is_indian_citizen": 1,
            "whatsapp_id": 5,
            "skype_id": 5,
            "neeri_relation": 5,
            "documents": 5,
            "education_details": 5,
            "experiences": 5,
            "references": 5,
            "overseas_visits": 5,
            "languages": 5,
            "published_papers": 5,
        }

        total = 0
        if self.gender:
            total += percent.get("gender", 0)

        if self.is_fresher:
            total += percent.get("is_fresher", 0)

        if self.date_of_birth:
            total += percent.get("date_of_birth", 0)

        if self.local_address:
            total += percent.get("local_address", 0)

        if self.permanent_address:
            total += percent.get("permanent_address", 0)

        if self.father_address:
            total += percent.get("father_address", 0)

        if self.date_of_birth_in_words:
            total += percent.get("date_of_birth_in_words", 0)

        if self.place_of_birth:
            total += percent.get("place_of_birth", 0)

        if self.father_name:
            total += percent.get("father_name", 0)

        if self.father_occupation:
            total += percent.get("father_occupation", 0)

        if self.religion:
            total += percent.get("religion", 0)

        if self.caste:
            total += percent.get("caste", 0)

        if self.passport_number:
            total += percent.get("passport_number", 0)

        if self.passport_expiry:
            total += percent.get("passport_expiry", 0)

        if self.profile_photo:
            total += percent.get("profile_photo", 0)

        if self.fax_number:
            total += percent.get("fax_number", 0)

        if self.is_indian_citizen:
            total += percent.get("is_indian_citizen", 0)

        if self.whatsapp_id:
            total += percent.get("whatsapp_id", 0)

        if self.skype_id:
            total += percent.get("skype_id", 0)

        if self.neeri_relation:
            total += percent.get("neeri_relation", 0)

        if self.documents:
            total += percent.get("documents", 0)

        if self.education_details:
            total += percent.get("education_details", 0)

        if self.experiences:
            total += percent.get("experiences", 0)

        if self.references:
            total += percent.get("references", 0)

        if self.overseas_visits:
            total += percent.get("overseas_visits", 0)

        if self.languages:
            total += percent.get("languages", 0)

        if self.published_papers:
            total += percent.get("published_papers", 0)

        return str(total) + " %"

    def __str__(self):
        return self.user.email


class NeeriUserProfile(BaseModel):
    GENDER_MALE = "male"
    GENDER_FEMALE = "female"

    GENDER_CHOICES = [
        (GENDER_MALE, "Male"),
        (GENDER_FEMALE, "Female"),
    ]

    SC = "sc"
    ST = "st"
    OBC = "obc"
    GEN = "gen"
    PWD = "pwd"

    CASTE_CHOICES = [
        (SC, "SC"),
        (ST, "ST"),
        (OBC, "OBC"),
        (GEN, "GEN"),
        (PWD, "PWD"),
    ]

    user = models.OneToOneField(
        "User", on_delete=models.CASCADE, related_name="neeri_user_profile"
    )
    gender = models.CharField(
        null=True, blank=True, choices=GENDER_CHOICES, max_length=20
    )
    # mobile_no = models.CharField(max_length=20, null=True, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    address = models.OneToOneField(
        "user.Location",
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name="neeri_user_address",
    )
    religion = models.CharField(max_length=30, null=True, blank=True)
    caste = models.CharField(
        max_length=30, choices=CASTE_CHOICES, null=True, blank=True
    )
    profile_photo = models.CharField(max_length=100, null=True, blank=True)
    roles = models.ManyToManyField(
        "user.RoleMaster", blank=True, null=True, related_name="neeri_user_roles"
    )

    def __str__(self):
        return self.user.email


class Location(BaseModel):
    address1 = models.CharField(max_length=200, blank=True)
    address2 = models.CharField(max_length=200, blank=True)
    address3 = models.CharField(max_length=200, null=True, blank=True)
    city = models.CharField(max_length=200, null=True, blank=True)
    state = models.CharField(max_length=200, null=True, blank=True)
    country = models.CharField(max_length=200, null=True, blank=True)
    postcode = models.CharField(max_length=20, null=True, blank=True)
    telephone_no = models.CharField(max_length=20, null=True, blank=True)

    def __str__(self):
        return u" ".join(
            [
                self.address1,
                self.address2,
                self.address3 or "",
                self.city or "",
                self.postcode or "",
                self.country,
            ]
        )


class RoleMaster(BaseModel):
    role_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    role_name = models.CharField(max_length=30, null=True, blank=True)

    def __str__(self):
        return self.role_name


class PermissionMaster(BaseModel):
    permission_id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False
    )
    permission_name = models.CharField(max_length=30, null=True, blank=True)

    def __str__(self):
        return self.permission_name


class UserRoles(BaseModel):
    role = models.ForeignKey(
        "RoleMaster",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="role_master",
    )
    user = models.ForeignKey(
        "User",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="user_role",
    )

    def __str__(self):
        return " ".join([self.user.email, self.role.role_name])


class UserPermissions(BaseModel):
    permission = models.ForeignKey(
        "PermissionMaster",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="permission",
    )
    role = models.ForeignKey(
        "RoleMaster",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="user",
    )

    def __str__(self):
        return " ".join([self.role.role_name, self.permission.permission_name])


class UserDocuments(BaseModel):
    doc_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    doc_file_path = models.CharField(
        max_length=200, null=True, blank=True, help_text="path to document"
    )
    doc_name = models.CharField(max_length=200, null=True, blank=True)

    def __str__(self):
        return self.doc_name


class OverseasVisits(BaseModel):
    USA = "usa"
    UK = "uk"

    COUNTRY_CHOICES = [
        (USA, "USA"),
        (UK, "UK"),
    ]

    country_visited = models.CharField(
        max_length=50, choices=COUNTRY_CHOICES, null=True, blank=True
    )
    date_of_visit = models.DateField(null=True, blank=True)
    duration_of_visit = models.CharField(max_length=50, null=True, blank=True)
    purpose_of_visit = models.CharField(max_length=50, null=True, blank=True)

    def __str__(self):
        return self.country_visited


class UserReference(BaseModel):
    reference_name = models.CharField(max_length=50, null=True, blank=True)
    position = models.CharField(max_length=50, null=True, blank=True)
    address = models.OneToOneField(
        "Location", on_delete=models.CASCADE, related_name="referee_address"
    )
    # TODO: email = models.OneToOneField('user.User', on_delete=models.CASCADE, related_name="user_email")

    def __str__(self):
        return self.reference_name


class NeeriRelation(BaseModel):
    relation_name = models.CharField(max_length=50, null=True, blank=True)
    designation = models.CharField(max_length=50, null=True, blank=True)
    center_name = models.CharField(max_length=50, null=True, blank=True)
    relation = models.CharField(max_length=50, null=True, blank=True)

    def __str__(self):
        return self.relation_name


class UserEducationDetails(BaseModel):
    PERCENTAGE = "%"
    CLASS = "class"
    DIVISION = "division"

    SCORE_UNIT_CHOICES = [
        (PERCENTAGE, "%"),
        (CLASS, "class"),
        (DIVISION, "division"),
    ]

    exam_name = models.CharField(max_length=50, null=True, blank=True)
    university = models.CharField(
        max_length=50, null=True, blank=True, help_text="university"
    )
    college_name = models.CharField(max_length=50, null=True, blank=True)
    passing_year = models.CharField(max_length=50, null=True, blank=True)
    score = models.CharField(max_length=50, null=True, blank=True, help_text="score")
    score_unit = models.CharField(
        max_length=30, choices=SCORE_UNIT_CHOICES, null=True, blank=True
    )
    specialization = models.CharField(
        max_length=50, null=True, blank=True, help_text="special subject"
    )

    def __str__(self):
        return self.specialization


class UserExperienceDetails(BaseModel):
    PERMANENT = "permanent"
    TEMPORARY = "temporary"

    EMPLOYMENT_TYPE_CHOICES = [
        (PERMANENT, "PERMANENT"),
        (TEMPORARY, "TEMPORARY"),
    ]
    employer_name = models.CharField(max_length=50, null=True, blank=True)
    post = models.CharField(max_length=30, null=True, blank=True)
    employed_from = models.DateField(null=True, blank=True)
    employed_to = models.DateField(null=True, blank=True)
    employment_type = models.CharField(
        max_length=30, choices=EMPLOYMENT_TYPE_CHOICES, null=True, blank=True
    )
    salary = models.IntegerField(null=True, blank=True)
    grade = models.CharField(max_length=30, null=True, blank=True)

    def __str__(self):
        return self.employer_name


class PublishedPapers(BaseModel):
    paper_title = models.CharField(max_length=30, null=True, blank=True)
    attachments = models.ManyToManyField(
        "user.UserDocuments", blank=True, related_name="attachments"
    )

    def __str__(self):
        return str(self.id)


class UserLanguages(BaseModel):
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    EXPERT = "expert"

    LEVEL_CHOICES = [
        (BEGINNER, "BEGINNER"),
        (INTERMEDIATE, "INTERMEDIATE"),
        (EXPERT, "EXPERT"),
    ]

    name = models.CharField(max_length=30, null=True, blank=True)
    read_level = models.CharField(
        max_length=20, choices=LEVEL_CHOICES, null=True, blank=True
    )
    write_level = models.CharField(
        max_length=20, choices=LEVEL_CHOICES, null=True, blank=True
    )
    speak_level = models.CharField(
        max_length=20, choices=LEVEL_CHOICES, null=True, blank=True
    )
    exam_passed = models.CharField(max_length=100, null=True, blank=True)

    def __str__(self):
        return str(self.id)


class ProfessionalTraining(BaseModel):
    title = models.CharField(max_length=200, null=True, blank=True)
    description = models.CharField(max_length=200, null=True, blank=True)
    from_date = models.DateField(null=True, blank=True)
    to_date = models.DateField(null=True, blank=True)

    def __str__(self):
        return str(self.id)


class OtherInformation(BaseModel):
    bond_title = models.CharField(max_length=100, null=True, blank=True)
    bond_details = models.TextField(null=True, blank=True)
    organisation_name = models.CharField(max_length=200, null=True, blank=True)
    bond_start_date = models.DateField(null=True, blank=True)
    bond_end_date = models.DateField(null=True, blank=True)
    notice_period_min = models.IntegerField(
        null=True, blank=True, help_text="notice_period_min_in_days"
    )
    notice_period_max = models.IntegerField(
        null=True, blank=True, help_text="notice_period_max_in_days"
    )

    def __str__(self):
        return str(self.id)


class UserAuthentication(models.Model):
    user = models.OneToOneField(
        "User", on_delete=models.CASCADE, related_name="user_auth"
    )
    email_verified = models.BooleanField(default=False)
    mobile_verified = models.BooleanField(default=False)
    # reset_verified = models.BooleanField(default=False)
    # email_otp = models.IntegerField(null=True, blank=True)
    email_token = models.CharField(max_length=200, null=True, blank=True)
    sms_token = models.CharField(max_length=200, null=True, blank=True)
    reset_token = models.CharField(max_length=200, null=True, blank=True)
    mobile_otp = models.IntegerField(null=True, blank=True)
    email_otp_expiry = models.DateTimeField(null=True, blank=True)
    mobile_otp_expiry = models.DateTimeField(null=True, blank=True)
    reset_otp_expiry = models.DateTimeField(null=True, blank=True)
    account_lock_expiry = models.DateTimeField(null=True, blank=True)
    is_first_login = models.BooleanField(blank=True, null=True, default=True)
    is_suspended = models.BooleanField(
        blank=True, null=True, default=False
    )  # is_active false  and is_suspended true
    is_locked = models.BooleanField(
        blank=True, null=True, default=False
    )  # is_active false  and is_locked true
    wrong_login_attempt = models.IntegerField(null=True, default=0, blank=True)

    def __str__(self):
        return self.user.email

    def save(self, **kwargs):
        self.email_otp_expiry = datetime.datetime.now() + datetime.timedelta(
            minutes=OTP_EXPIRY_TIME
        )
        self.mobile_otp_expiry = datetime.datetime.now() + datetime.timedelta(
            minutes=OTP_EXPIRY_TIME
        )
        self.reset_otp_expiry = datetime.datetime.now() + datetime.timedelta(
            minutes=OTP_EXPIRY_TIME
        )
        self.account_lock_expiry = datetime.datetime.now() + datetime.timedelta(
            minutes=ACCOUNT_LOCKED_TIME
        )
        super(UserAuthentication, self).save(**kwargs)


class MentorMaster(BaseModel):
    mentor_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    mentor_name = models.CharField(max_length=150, null=True, blank=True)

    def __str__(self):
        return self.mentor_name


# Trainee ID	PK
# Department (division)	dropdown
# Mentor	dropdown
# Trainee Name
# Email
# Mobile
# EmploymentStartDate
# EmploymentEndDate
# Status	enum	Yet to join, Active, Completed

NOT_DECIDED = "not_decided"
ACTIVE = "active"
COMPLETED = "completed"
YET_TO_JOIN = "yet to join"

STATUS_CHOICES = [
    (NOT_DECIDED, "NOT_DECIDED"),
    (ACTIVE, "ACTIVE"),
    (COMPLETED, "COMPLETED"),
    (YET_TO_JOIN, "YET_TO_JOIN"),
]


class Trainee(BaseModel):
    trainee_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    generated_trainee_id = models.CharField(
        max_length=16, blank=True, null=True, default=None, unique=True
    )
    division = models.ForeignKey(
        "job_posting.Division",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="division_trainee",
    )
    mentor = models.ForeignKey(
        "user.MentorMaster",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="mentor",
    )
    trainee_name = models.CharField(max_length=150, null=True, blank=True)
    email = models.EmailField(unique=True, validators=[EmailValidator()])
    mobile_no = models.CharField(max_length=10, unique=True, null=True)
    emp_start_date = models.DateField(null=True, blank=True)
    emp_end_date = models.DateField(null=True, blank=True)
    status = models.CharField(
        null=True,
        blank=True,
        choices=STATUS_CHOICES,
        default=NOT_DECIDED,
        max_length=20,
    )

    def save(self, **kwargs):
        prefix = "TRN-"
        number = "{:09d}".format(random.randrange(1, 999999999))
        self.generated_trainee_id = prefix + number
        super(Trainee, self).save(**kwargs)
        # if not self.generated_trainee_id:
        #     self.generated_trainee_id = get_random_string(length=9)
        # super(Trainee, self).save(**kwargs)


class RelaxationCategoryMaster(BaseModel):
    relaxation_cat_id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False
    )
    relaxation_category = models.CharField(max_length=150, null=True, blank=True)

    def __str__(self):
        return self.relaxation_category


class RelaxationMaster(BaseModel):
    relaxation_rule_id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False
    )
    relaxation = models.ForeignKey(
        "user.RelaxationCategoryMaster",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="relaxation",
    )
    age_relaxation = models.PositiveIntegerField(null=True, blank=True)
    fee_relaxation = models.PositiveIntegerField(null=True, blank=True)

    def __str__(self):
        return self.relaxation.relaxation_category


class Subscription(BaseModel):
    user = models.ForeignKey(
        "User", related_name="subscription", on_delete=models.CASCADE
    )
    start_date = models.DateField()
    end_date = models.DateField()
    expired = models.BooleanField(default=False)

    def __str__(self):
        return self.user.email
