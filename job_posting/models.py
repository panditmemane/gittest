from django.db import models
import uuid

from django.db.models import CharField

from user.models import BaseModel
from django.contrib.postgres.fields import ArrayField


class Department(BaseModel):
    dept_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    dept_name = models.CharField(max_length=50, null=True, blank=True)

    def __str__(self):
        return self.dept_name


class Division(BaseModel):
    division_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    division_name = models.CharField(max_length=50, null=True, blank=True)

    def __str__(self):
        return self.division_name


class ZonalLab(BaseModel):
    zonal_lab_id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False
    )
    zonal_lab_name = models.CharField(max_length=50, null=True, blank=True)

    def __str__(self):
        return self.zonal_lab_name


class QualificationMaster(BaseModel):
    qualification_id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, unique=True, editable=False
    )
    qualification = models.CharField(max_length=300, null=True, blank=True)
    short_code = ArrayField(
        CharField(max_length=300, blank=True, null=True), null=True, blank=True
    )

    def __str__(self):
        return self.qualification


class QualificationJobHistoryMaster(BaseModel):
    qualification_job_id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False
    )
    qualification = models.CharField(max_length=300, null=True, blank=True)
    short_code = ArrayField(
        CharField(max_length=300, blank=True, null=True), null=True, blank=True
    )

    def __str__(self):
        return self.qualification


# Position ID
# Position Name
# Position Display Name
# Minimum Age
# Maximum Age
# Required Document
# Required Information
# Qualification Degrees ?
# Qualification Job History ?


class NewPositionMaster(BaseModel):
    position_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    position_name = models.CharField(max_length=300, null=True, blank=True)
    position_display_name = models.CharField(max_length=300, null=True, blank=True)
    min_age = models.PositiveIntegerField(blank=True, null=True)
    max_age = models.PositiveIntegerField(blank=True, null=True)
    qualification_desc = models.TextField(null=True, blank=True)
    documents_required = models.ManyToManyField(
        "document.NewDocumentMaster",
        blank=True,
        related_name="position_master_required_documents",
    )
    information_required = models.ManyToManyField(
        "document.InformationMaster", blank=True, related_name="required_info"
    )
    qualification = models.ManyToManyField(
        "QualificationMaster", blank=True, related_name="qualification_master_position"
    )
    qualification_job_history = models.ManyToManyField(
        "QualificationJobHistoryMaster",
        blank=True,
        related_name="qualification_job_history",
    )

    def __str__(self):
        return str(self.position_display_name)


# Grade I, Grade II, Grade III, Grade IV, Grade V
# Level I, Level II, Level III, Level IV

I = "I"
II = "II"
III = "III"
IV = "IV"
V = "V"

GRADE_CHOICES = [
    (I, "I"),
    (II, "II"),
    (III, "III"),
    (IV, "IV"),
    (V, "V"),
]
LEVEL_CHOICES = [
    (I, "I"),
    (II, "II"),
    (III, "III"),
    (IV, "IV"),
]


class PermanentPositionMaster(BaseModel):
    perm_position_id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False
    )

    perm_position_master = models.ForeignKey(
        "NewPositionMaster",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="perm_positon",
    )
    grade = models.CharField(
        max_length=30, choices=GRADE_CHOICES, null=True, blank=True
    )
    level = models.CharField(
        max_length=30, choices=LEVEL_CHOICES, null=True, blank=True
    )

    def __str__(self):
        return self.perm_position_master.position_display_name


HRA = "hra"
CONSOLIDATED = "consolidated"

ALLOWANCE_CHOICES = [
    (HRA, "HRA"),
    (CONSOLIDATED, "CONSOLIDATED"),
]


class TemporaryPositionMaster(BaseModel):
    temp_position_id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False
    )
    temp_position_master = models.ForeignKey(
        "NewPositionMaster",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="temp_positon",
    )
    allowance = models.CharField(
        max_length=30, choices=ALLOWANCE_CHOICES, null=True, blank=True
    )
    salary = models.FloatField(null=True, blank=True)

    def __str__(self):
        return self.temp_position_master.position_display_name


class PositionQualificationMapping(BaseModel):
    HRA = "hra"
    CONSOLIDATED = "consolidated"

    ALLOWANCE_CHOICES = [
        (HRA, "HRA"),
        (CONSOLIDATED, "CONSOLIDATED"),
    ]

    position = models.ForeignKey(
        "NewPositionMaster",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="postion",
    )
    position_display_name = models.CharField(max_length=300, null=True)
    documents_required = models.ManyToManyField(
        "document.NewDocumentMaster",
        blank=True,
        related_name="position_qualification_required_documents",
    )
    information_required = models.ManyToManyField(
        "document.InformationMaster", blank=True, related_name="position_required_info"
    )
    qualification = models.ManyToManyField(
        "QualificationMaster", blank=True, related_name="position_qualification"
    )
    qualification_job_history = models.ManyToManyField(
        "QualificationJobHistoryMaster",
        blank=True,
        related_name="position_qualification_job_history",
    )
    min_age = models.IntegerField(blank=True, null=True)
    max_age = models.IntegerField(blank=True, null=True)
    number_of_vacancies = models.IntegerField(
        null=True, blank=True, help_text="total number of vacancies for post"
    )
    monthly_emolements = models.CharField(max_length=80, null=True, blank=True)
    allowance = models.CharField(
        max_length=30, choices=ALLOWANCE_CHOICES, null=True, blank=True
    )
    grade = models.CharField(
        max_length=30, choices=GRADE_CHOICES, null=True, blank=True
    )
    level = models.CharField(
        max_length=30, choices=LEVEL_CHOICES, null=True, blank=True
    )
    extra_note = models.TextField(null=True, blank=True)

    def __str__(self):
        return self.position.position_display_name


class JobTemplate(BaseModel):
    """
    This model will be same as PositionQualificationMapping, it will be useful when we need to
    use existing PositionQualificationMappings as a template. It will allow Job_Posting User to
    autopopulate job position saved as template.
    """

    HRA = "hra"
    CONSOLIDATED = "consolidated"

    ALLOWANCE_CHOICES = [
        (HRA, "HRA"),
        (CONSOLIDATED, "CONSOLIDATED"),
    ]

    template_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    template_name = models.CharField(max_length=50, null=True, blank=True)
    position = models.ForeignKey(
        "NewPositionMaster",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="job_postion",
    )
    qualification = models.ManyToManyField(
        "QualificationMaster", blank=True, related_name="job_qualification"
    )
    min_age = models.IntegerField(blank=True, null=True)
    max_age = models.IntegerField(blank=True, null=True)
    number_of_vacancies = models.IntegerField(
        null=True, blank=True, help_text="total number of vacancies for post"
    )
    monthly_emolements = models.CharField(max_length=80, null=True, blank=True)
    allowance = models.CharField(
        max_length=30, choices=ALLOWANCE_CHOICES, null=True, blank=True
    )
    extra_note = models.TextField(null=True, blank=True)

    def __str__(self):
        return self.template_name


class JobDocuments(BaseModel):
    doc_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    doc_file_path = models.CharField(
        max_length=200, null=True, blank=True, help_text="path to document"
    )
    doc_name = models.CharField(max_length=200, null=True, blank=True)

    def __str__(self):
        return self.doc_name


class JobPosting(BaseModel):
    Contract_Basis = "Contract_Basis"
    Permanent = "Permanent"

    JOB_TYPE_CHOICES = [
        (Contract_Basis, "contract_basis"),
        (Permanent, "permanent"),
    ]

    SCHEDULED = "scheduled"
    PUBLISHED = "published"
    SUSPENDED = "suspended"
    CANCELLED = "cancelled"
    CLOSED = "closed"
    ARCHIVED = "Archived"

    STATUS_CHOICES = [
        (SCHEDULED, "Scheduled"),
        (PUBLISHED, "Published"),
        (SUSPENDED, "Suspended"),
        (CANCELLED, "Cancelled"),
        (CLOSED, "Closed"),
        (ARCHIVED, "Archived"),
    ]

    job_posting_id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False, unique=True
    )
    notification_id = models.CharField(max_length=100, null=True, blank=True)
    notification_title = models.CharField(max_length=50, null=True, blank=True)
    ad_approval_id = models.CharField(max_length=50, null=True, blank=True)
    pre_ad_description = models.TextField(null=True, blank=True)
    post_ad_description = models.TextField(null=True, blank=True)
    project_number = models.ForeignKey(
        "JobPostingRequirement",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="job_posting_project_number",
    )
    division = models.ForeignKey(
        "Division",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="division",
    )
    zonal_lab = models.ForeignKey(
        "ZonalLab",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="zonal_lab",
    )
    publication_date = models.DateTimeField(
        null=True, blank=True, help_text="start date of job notification"
    )
    end_date = models.DateTimeField(
        null=True, blank=True, help_text="end date of job notification"
    )
    documents_required = models.ManyToManyField(
        "document.NewDocumentMaster", blank=True, related_name="required_documents"
    )
    documents_uploaded = models.ManyToManyField(
        "JobDocuments", blank=True, null=True, related_name="documents"
    )
    office_memorandum = models.ForeignKey(
        "JobDocuments",
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name="office_memo",
    )
    # documents will be the attached documents(Office Memorandum,Appendices)
    status = models.CharField(
        null=True, blank=True, choices=STATUS_CHOICES, max_length=30
    )
    job_type = models.CharField(
        null=True, blank=True, choices=JOB_TYPE_CHOICES, max_length=30
    )
    manpower_positions = models.ManyToManyField(
        "PositionQualificationMapping", blank=True, related_name="job_positions"
    )

    # agewise_relaxation = models.IntegerField(blank=True, null=True)
    # percentwise_relaxation = models.IntegerField(blank=True, null=True)

    def __str__(self):
        return self.notification_title


class UserJobPositions(BaseModel):
    DOCUMENT_PENDING = "document pending"
    RECEIVED = "received"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    SHORTLISTED = "shortlisted"
    OFFERED = "offered"
    HIRED = "hired"
    INTERVIEW = "interview"
    AWAITING_REVIEW = "awaiting review"
    CLOSED = "closed"
    APPEALED = "appealed"

    APPLIED_JOB_STATUS_CHOICES = [
        (DOCUMENT_PENDING, "DOCUMENT_PENDING"),
        (RECEIVED, "RECEIVED"),
        (ACCEPTED, "ACCEPTED"),
        (REJECTED, "REJECTED"),
        (SHORTLISTED, "SHORTLISTED"),
        (OFFERED, "OFFERED"),
        (HIRED, "HIRED"),
        (INTERVIEW, "INTERVIEW"),
        (AWAITING_REVIEW, "AWAITING_REVIEW"),
        (CLOSED, "CLOSED"),
        (APPEALED, "APPEALED"),
    ]

    user = models.ForeignKey(
        "user.User",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="user",
    )
    job_posting = models.ForeignKey(
        "JobPosting",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="job_posting_applicants",
    )
    position = models.ForeignKey(
        "PositionQualificationMapping",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="job_position",
    )
    applied_job_status = models.CharField(
        max_length=50, choices=APPLIED_JOB_STATUS_CHOICES, blank=True, null=True
    )
    appeal = models.ForeignKey(
        "AppealMaster",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="appeal",
    )
    reason_to_appeal = models.TextField(blank=True, null=True)
    date_of_application = models.DateField(auto_now_add=True)
    date_of_closing = models.DateField(
        blank=True, null=True, help_text="Closing date of JobPosting"
    )
    user_job_position_id = models.CharField(
        max_length=200, null=True, blank=True
    )  # It will be like notifiction_id/job_posting_id/user_id/position_id

    documents = models.ManyToManyField(
        "user.UserDocuments",
        blank=True,
        related_name="application_documents",
    )

    def __str__(self):
        return self.job_posting.notification_title


class AppealMaster(BaseModel):
    appeal_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    appeal_reason_master = models.CharField(max_length=200, blank=True, null=True)

    def __str__(self):
        return self.appeal_reason_master


class JobPostingRequirementPositions(BaseModel):
    position = models.ForeignKey(
        "TemporaryPositionMaster",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="positions_position",
    )
    job_posting_requirement = models.ForeignKey(
        "JobPostingRequirement",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="manpower_position",
    )
    count = models.IntegerField(blank=True, null=True)
    total_cost = models.FloatField(null=True, blank=True)

    """
    def save(self, *args, **kwargs):
        self.total_cost = self.position.salary * self.count
        print("hello", self.total_cost)
        # return total_cost
        super(JobPostingRequirementPositions, self).save(*args, **kwargs)
    """

    def __str__(self):
        return self.position.temp_position_master.position_name


# Draft, Submit, Lock, Approve, Reject, Cancel

DRAFT = "draft"
SUBMIT = "submit"
LOCK = "lock"
SUSPENDED = "suspended"
APPROVE = "approve"
REJECT = "reject"
CANCEL = "cancel"

STATUS_CHOICES = [
    (DRAFT, "DRAFT"),
    (SUBMIT, "SUBMIT"),
    (LOCK, "LOCK"),
    (SUSPENDED, "SUSPENDED"),
    (REJECT, "REJECT"),
    (CANCEL, "CANCEL"),
]


class JobPostingRequirement(BaseModel):
    division_name = models.ForeignKey(
        "Division",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="job_posting_requirement_division",
    )
    zonal_lab = models.ForeignKey(
        "ZonalLab",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="job_posting_requirement_zonal_lab",
    )
    project_title = models.CharField(max_length=200, null=True, blank=True)
    project_number = models.CharField(max_length=30, null=True, blank=True)
    project_start_date = models.DateField(
        blank=True, null=True, help_text="Starting date of project"
    )
    project_end_date = models.DateField(
        blank=True, null=True, help_text="Closing date of project"
    )
    manpower_positions = models.ManyToManyField(
        "TemporaryPositionMaster",
        through=JobPostingRequirementPositions,
        blank=True,
        related_name="job_positions",
    )
    provisions_made = models.BooleanField(blank=True, null=True)
    total_estimated_amount = models.IntegerField(null=True, blank=True)
    min_essential_qualification = models.CharField(
        max_length=200, null=True, blank=True
    )
    job_requirements = models.CharField(max_length=200, null=True, blank=True)
    desired_qualification = models.CharField(max_length=200, null=True, blank=True)
    status = models.CharField(
        null=True, blank=True, choices=STATUS_CHOICES, max_length=30
    )

    def __str__(self):
        return self.project_number


class SelectionProcessContent(BaseModel):
    description = models.CharField(max_length=200, null=True, blank=True)
    selection_committee = models.ManyToManyField(
        "SelectionCommitteeMaster", blank=True, related_name="selection_committee"
    )

    def __str__(self):
        return str(self.pk)


class SelectionCommitteeMaster(BaseModel):
    committee_id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False
    )
    committee_name = models.CharField(max_length=200, null=True, blank=True)

    def __str__(self):
        return self.committee_name


class ServiceConditions(BaseModel):
    title = models.CharField(max_length=200, null=True, blank=True)
    description = models.TextField(null=True, blank=True)

    def __str__(self):
        return str(self.pk)


class FeeMaster(models.Model):
    fee = models.FloatField()
    category = models.CharField(choices=JobPosting.JOB_TYPE_CHOICES, max_length=30)

    def __str__(self):
        return self.category
