from django.contrib import admin
from django.contrib.admin import register
from job_posting.models import (
    Department,
    Division,
    ZonalLab,
    QualificationMaster,
    PositionQualificationMapping,
    JobPosting,
    JobTemplate,
    UserJobPositions,
    JobPostingRequirement,
    JobPostingRequirementPositions,
    JobDocuments,
    SelectionCommitteeMaster,
    SelectionProcessContent,
    ServiceConditions,
    AppealMaster,
    TemporaryPositionMaster,
    PermanentPositionMaster,
    NewPositionMaster,
    QualificationJobHistoryMaster,
    FeeMaster,
)


@register(ServiceConditions)
class ServiceConditionsAdmin(admin.ModelAdmin):
    list_display = ["title", "description"]


@register(SelectionCommitteeMaster)
class SelectionCommitteeMasterAdmin(admin.ModelAdmin):
    list_display = ["committee_id", "committee_name"]


@register(SelectionProcessContent)
class SelectionProcessContentAdmin(admin.ModelAdmin):
    list_display = ["description"]


@register(Department)
class DepartmentAdmin(admin.ModelAdmin):
    list_display = ["dept_id", "dept_name"]


@register(JobDocuments)
class JobDocumentsAdmin(admin.ModelAdmin):
    list_display = ["doc_id", "doc_file_path", "doc_name"]


@register(Division)
class DivisionAdmin(admin.ModelAdmin):
    list_display = ["division_id", "division_name", "is_deleted"]


@register(AppealMaster)
class AppealMasterAdmin(admin.ModelAdmin):
    list_display = ["appeal_id", "appeal_reason_master", "is_deleted"]


@register(ZonalLab)
class ZonalLabAdmin(admin.ModelAdmin):
    list_display = ["zonal_lab_id", "zonal_lab_name", "is_deleted"]


@register(QualificationMaster)
class QualificationMasterAdmin(admin.ModelAdmin):
    list_display = ["qualification_id", "qualification", "short_code"]


@register(QualificationJobHistoryMaster)
class QualificationJobHistoryMasterAdmin(admin.ModelAdmin):
    list_display = ["qualification_job_id", "qualification", "short_code"]


@register(PositionQualificationMapping)
class PositionQualificationMappingAdmin(admin.ModelAdmin):
    list_display = [
        "position",
        "min_age",
        "max_age",
        "number_of_vacancies",
        "monthly_emolements",
        "allowance",
        "extra_note",
    ]


@register(JobTemplate)
class JobTemplateAdmin(admin.ModelAdmin):
    list_display = ["template_id", "template_name", "position"]


@register(JobPosting)
class JobPostingAdmin(admin.ModelAdmin):
    list_display = [
        "job_posting_id",
        "notification_id",
        "notification_title",
        "project_number",
        "division",
        "zonal_lab",
        "publication_date",
        "end_date",
        "status",
    ]


@register(UserJobPositions)
class UserJobPositionsAdmin(admin.ModelAdmin):
    list_display = [
        "user",
        "job_posting",
        "position",
        "applied_job_status",
        "appeal",
        "date_of_application",
        "date_of_closing",
        "user_job_position_id",
    ]


class JobPostingRequirementPositionsAdmin(admin.TabularInline):
    # list_display = ['position', 'salary', 'count', 'is_deleted']
    model = JobPostingRequirementPositions
    exclude = ("created_by", "updated_by", "created_at", "updated_at", "is_deleted")


@register(JobPostingRequirement)
class JobPostingRequirementAdmin(admin.ModelAdmin):
    list_display = [
        "division_name",
        "zonal_lab",
        "project_title",
        "project_number",
        "status",
        "is_deleted",
    ]
    inlines = [
        JobPostingRequirementPositionsAdmin,
    ]


# NewPositionMaster
@register(NewPositionMaster)
class NewPositionMasterAdmin(admin.ModelAdmin):
    list_display = [
        "position_id",
        "position_name",
        "position_display_name",
        "is_deleted",
    ]


# perm position & temp position


@register(PermanentPositionMaster)
class PermanentPositionMasterAdmin(admin.ModelAdmin):
    list_display = ["perm_position_id", "grade", "level", "is_deleted"]


@register(TemporaryPositionMaster)
class TemporaryPositionMasterAdmin(admin.ModelAdmin):
    list_display = ["temp_position_id", "allowance", "salary", "is_deleted"]


@register(FeeMaster)
class FeeAdmin(admin.ModelAdmin):
    pass
