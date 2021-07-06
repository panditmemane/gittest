from django.db.transaction import atomic
from rest_framework.filters import SearchFilter
from rest_framework.generics import ListAPIView, RetrieveAPIView, RetrieveUpdateAPIView
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView

from job_posting.models import (
    Department,
    Division,
    ZonalLab,
    QualificationMaster,
    PositionQualificationMapping,
    JobPostingRequirement,
    JobPosting,
    SelectionProcessContent,
    ServiceConditions,
    UserJobPositions,
    AppealMaster,
    NewPositionMaster,
    PermanentPositionMaster,
    TemporaryPositionMaster,
    QualificationJobHistoryMaster,
    FeeMaster,
)
from job_posting.serializer import (
    DepartmentSerializer,
    DivisionSerializer,
    ZonalLabSerializer,
    QualificationMasterSerializer,
    ProjectApprovalListSerializer,
    PositionQualificationMappingSerializer,
    JobTemplateSerializer,
    JobPostingSerializer,
    SelectionProcessContentSerializer,
    ServiceConditionsSerializer,
    UserJobPositionsSerializer,
    ProjectRequirementSerializer,
    UserAppealForJobPositionsSerializer,
    AppealReasonMasterSerializer,
    NewPositionMasterSerializer,
    PermanentPositionMasterSerializer,
    TemporaryPositionMasterSerializer,
    ProjectRequirementApprovalStatusSerializer,
    QualificationJobHistoryMasterSerializer,
    PublicJobPostSerializer,
)

from rest_framework import status
from rest_framework.response import Response

from user.models import UserDocuments


class QualificationMasterSearchListView(ListAPIView):
    queryset = QualificationMaster.objects.all()
    serializer_class = QualificationMasterSerializer
    filter_backends = [SearchFilter]
    search_fields = ("qualification_id", "qualification", "short_code")


class QualificationJobHistoryMasterSearchListView(ListAPIView):
    queryset = QualificationJobHistoryMaster.objects.all()
    serializer_class = QualificationJobHistoryMasterSerializer
    filter_backends = [SearchFilter]
    search_fields = ("qualification_job_id", "qualification", "short_code")


class RetrieveQualificationMasterView(APIView):
    def get(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        qual = QualificationMaster.objects.get(qualification_id=id, is_deleted=False)
        serializer = QualificationMasterSerializer(qual)
        return Response(serializer.data, status=200)


class DeleteQualificationMasterView(APIView):
    def delete(self, request, *args, **kwargs):
        try:
            id = self.kwargs["id"]
            qualification = QualificationMaster.objects.get(qualification_id=id)
            qualification.is_deleted = True
            qualification.save()
            return Response(
                data={"message": "Record Deleted Successfully(Soft Delete)."},
                status=200,
            )
        except:
            return Response(data={"message": "Details Not Found."}, status=401)


class UpdateQualificationMasterView(APIView):
    def put(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        qualification = QualificationMaster.objects.get(qualification_id=id)
        data = self.request.data
        serializer = QualificationMasterSerializer(qualification, data=data)
        serializer.is_valid(raise_exception=True)
        serializer.update(instance=qualification, validated_data=data)
        return Response(serializer.data, status=200)


class CreateQualificationMasterView(APIView):
    def post(self, request, *args, **kwargs):
        data = self.request.data
        serializer = QualificationMasterSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=200)


class QualificationMasterListView(APIView):
    def get(self, request, *args, **kwargs):
        docs = QualificationMaster.objects.filter(is_deleted=False).order_by('qualification')
        serializer = QualificationMasterSerializer(docs, many=True)
        return Response(serializer.data, status=200)


# Qualification Job History


class QualificationJobHistoryMasterView(APIView):
    def get(self, request, *args, **kwargs):
        try:
            qualification_job_id = self.kwargs["id"]
            if QualificationJobHistoryMaster.objects.filter(
                qualification_job_id=qualification_job_id, is_deleted=False
            ).exists():
                qual = QualificationJobHistoryMaster.objects.get(
                    qualification_job_id=qualification_job_id, is_deleted=False
                )
                serializer = QualificationJobHistoryMasterSerializer(qual)
                return Response(serializer.data, status=200)
            else:
                return Response(data={"message": "Details Not Found."}, status=401)
        except:
            docs = QualificationJobHistoryMaster.objects.filter(is_deleted=False).order_by('qualification')
            serializer = QualificationJobHistoryMasterSerializer(docs, many=True)
            return Response(serializer.data, status=200)

    def delete(self, request, *args, **kwargs):
        try:
            id = self.kwargs["id"]
            qualification = QualificationJobHistoryMaster.objects.get(
                qualification_job_id=id
            )
            qualification.is_deleted = True
            qualification.save()
            return Response(
                data={"message": "Record Deleted Successfully(Soft Delete)."},
                status=200,
            )
        except:
            return Response(data={"message": "Details Not Found."}, status=401)

    def put(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        qualification = QualificationJobHistoryMaster.objects.get(
            qualification_job_id=id
        )
        data = self.request.data
        serializer = QualificationJobHistoryMasterSerializer(qualification, data=data)
        serializer.is_valid(raise_exception=True)
        serializer.update(instance=qualification, validated_data=data)
        return Response(serializer.data, status=200)

    def post(self, request, *args, **kwargs):
        data = self.request.data
        serializer = QualificationJobHistoryMasterSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=200)


class DepartmentListView(APIView):
    def get(self, request, *args, **kwargs):
        if Department.objects.filter(is_deleted=False).count() > 0:
            departments = Department.objects.filter(is_deleted=False)
            serializer = DepartmentSerializer(departments, many=True)
            return Response(serializer.data, status=200)
        else:
            return Response(data={"messege": "No Records found"}, status=404)


class DivisionListView(APIView):
    def get(self, request, *args, **kwargs):
        try:
            division_id = self.kwargs["id"]
            divisions = Division.objects.get(division_id=division_id, is_deleted=False)
            serializer = DivisionSerializer(divisions)
            return Response(serializer.data, status=200)
        except:
            if Division.objects.filter(is_deleted=False).count() > 0:
                divisions = Division.objects.filter(is_deleted=False).order_by('division_name')
                serializer = DivisionSerializer(divisions, many=True)
                return Response(serializer.data, status=200)
            else:
                return Response(data={"message": "No Records found"}, status=404)

    # class DeleteDivisionMasterView(APIView):
    def delete(self, request, *args, **kwargs):
        try:
            id = self.kwargs["id"]
            division = Division.objects.get(division_id=id)
            division.is_deleted = True
            division.save()
            return Response(
                data={"message": "Record Deleted Successfully(Soft Delete)."},
                status=200,
            )
        except:
            return Response(data={"message": "Details Not Found."}, status=401)

    # class UpdateDivisionMasterView(APIView):
    def put(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        division = Division.objects.get(division_id=id)
        data = self.request.data
        serializer = DivisionSerializer(division, data=data)
        serializer.is_valid(raise_exception=True)
        serializer.update(instance=division, validated_data=data)
        return Response(serializer.data, status=200)

    # class CreateDivisionMasterView(APIView):
    def post(self, request, *args, **kwargs):
        data = self.request.data
        serializer = DivisionSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=200)


class ZonalLabListView(APIView):
    def post(self, request, *args, **kwargs):
        data = self.request.data
        serializer = ZonalLabSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=200)

    def get(self, request, *args, **kwargs):
        try:
            lab_id = self.kwargs["id"]
            labs = ZonalLab.objects.get(zonal_lab_id=lab_id, is_deleted=False)
            serializer = ZonalLabSerializer(labs)
            return Response(serializer.data, status=200)
        except:
            if ZonalLab.objects.filter(is_deleted=False).count() > 0:
                labs = ZonalLab.objects.filter(is_deleted=False).order_by('zonal_lab_name')
                serializer = ZonalLabSerializer(labs, many=True)
                return Response(serializer.data, status=200)
            else:
                return Response(data={"messege": "No Records found"}, status=404)

    def put(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        labs = ZonalLab.objects.get(zonal_lab_id=id)
        data = self.request.data
        serializer = ZonalLabSerializer(labs, data=data)
        serializer.is_valid(raise_exception=True)
        serializer.update(instance=labs, validated_data=data)
        return Response(serializer.data, status=200)

    def delete(self, request, *args, **kwargs):
        try:
            id = self.kwargs["id"]
            labs = ZonalLab.objects.get(zonal_lab_id=id)
            labs.is_deleted = True
            labs.save()
            return Response(
                data={"message": "Record Deleted Successfully(Soft Delete)."},
                status=200,
            )
        except:
            return Response(data={"message": "Details Not Found."}, status=401)


class ProjectApprovalListView(APIView):
    def get(self, request, *args, **kwargs):
        req = JobPostingRequirement.objects.filter(is_deleted=False)
        serializer = ProjectApprovalListSerializer(req, many=True)
        return Response(serializer.data, status=200)


class ProjectApprovalStatusListView(APIView):
    def get(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        if JobPostingRequirement.objects.filter(id=id, is_deleted=False).exists():
            job = JobPostingRequirement.objects.get(id=id, is_deleted=False)
            serializer = ProjectRequirementApprovalStatusSerializer(job)
            return Response(serializer.data, status=200)
        else:
            return Response(data={"message": "Details Not Found."}, status=401)

    def put(self, request, *args, **kwargs):
        data = self.request.data
        id = self.kwargs["id"]
        project = JobPostingRequirement.objects.get(id=id, is_deleted=False)
        serializer = ProjectRequirementApprovalStatusSerializer(project, data=data)
        serializer.is_valid(raise_exception=True)
        result = serializer.update(instance=project, validated_data=data)
        print("result=========", result)
        project = JobPostingRequirement.objects.get(id=result)
        serializer = ProjectRequirementApprovalStatusSerializer(project)
        return Response(serializer.data, status=200)


# project Requirement


class UpdateProjectRequirementView(APIView):
    def put(self, request, *args, **kwargs):
        data = self.request.data
        id = self.kwargs["id"]
        project = JobPostingRequirement.objects.get(id=id, is_deleted=False)
        serializer = ProjectRequirementSerializer(project, data=data)
        serializer.is_valid(raise_exception=True)
        result = serializer.update(instance=project, validated_data=data)
        project = JobPostingRequirement.objects.get(id=result)
        serializer = ProjectRequirementSerializer(project)
        return Response(serializer.data, status=200)


class CreateProjectRequirementView(APIView):
    def post(self, request, *args, **kwargs):
        data = self.request.data
        serializer = ProjectRequirementSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        result = serializer.save(validated_data=data)
        job_posting = JobPostingRequirement.objects.get(id=result)
        serializer = ProjectRequirementSerializer(job_posting)
        return Response(serializer.data, status=200)


class DeleteProjectRequirementView(APIView):
    def delete(self, request, *args, **kwargs):
        try:
            id = self.kwargs["id"]
            project = JobPostingRequirement.objects.get(id=id)
            project.is_deleted = True
            project.save()
            return Response(
                data={"message": "Record Deleted Successfully(Soft Delete)."},
                status=200,
            )
        except:
            return Response(data={"message": "Details Not Found."}, status=401)


class ProjectRequirementListView(APIView):
    def get(self, request, *args, **kwargs):
        job = JobPostingRequirement.objects.filter(is_deleted=False)
        serializer = ProjectRequirementSerializer(job, many=True)
        return Response(serializer.data, status=200)


class ProjectApprovalFilterListView(ListAPIView):
    queryset = JobPostingRequirement.objects.all()
    serializer_class = ProjectRequirementSerializer
    filterset_fields = [
        "division_name__division_name",
        "zonal_lab__zonal_lab_name",
        "project_number",
        "status",
        "manpower_position__position",
        "project_start_date",
        "project_end_date",
    ]


class ProjectApprovalSearchListView(ListAPIView):
    queryset = JobPostingRequirement.objects.all()
    serializer_class = ProjectRequirementSerializer
    filter_backends = [SearchFilter]
    search_fields = ("project_title", "job_requirements", "desired_qualification")


class RetrieveProjectRequirementView(APIView):
    def get(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        if JobPostingRequirement.objects.filter(id=id, is_deleted=False).exists():
            job = JobPostingRequirement.objects.get(id=id, is_deleted=False)
            serializer = ProjectRequirementSerializer(job)
            return Response(serializer.data, status=200)
        else:
            return Response(data={"message": "Details Not Found."}, status=401)


class PositionQualificationMappingListView(APIView):
    def get(self, request, *args, **kwargs):
        projects = PositionQualificationMapping.objects.filter(is_deleted=False)
        serializer = PositionQualificationMappingSerializer(projects, many=True)
        return Response(serializer.data, status=200)


class JobTemplateCreateView(APIView):
    def post(self, request, *args, **kwargs):
        data = self.request.data
        for template_data in data:
            serializer = JobTemplateSerializer(data=template_data)
            serializer.is_valid(raise_exception=True)
            serializer.save(validated_data=template_data)
        return Response(data={"message": "Template Saved Successfully"}, status=200)

    # def get(self, request, *args, **kwargs):
    #     projects = JobTemplate.objects.filter(is_deleted=False)
    #     serializer = JobTemplateSerializer(projects, many=True)
    #     return Response(serializer.data, status=200)


class JobPostingCreateView(APIView):
    @atomic
    def post(self, request, *args, **kwargs):
        try:
            data = self.request.data
            serializer = JobPostingSerializer(data=data)
            if serializer.is_valid():
                result = serializer.save(validated_data=data)
                job_posting = JobPosting.objects.get(job_posting_id=result)
                serializer = JobPostingSerializer(job_posting)
                return Response(serializer.data, status=200)
            else:
                return Response(data={"errors": serializer.errors})
        except Exception as e:
            return Response(data={"errors": str(e)})


class JobPostingDetailView(RetrieveUpdateAPIView):
    queryset = JobPosting.objects.filter(is_deleted=False)
    serializer_class = JobPostingSerializer
    lookup_field = "job_posting_id"
    lookup_url_kwarg = "id"

    @atomic
    def put(self, request, *args, **kwargs):
        data = self.request.data
        job_posting_id = self.kwargs["id"]
        job_posting = JobPosting.objects.get(job_posting_id=job_posting_id)
        serializer = JobPostingSerializer(job_posting, data=data)
        if serializer.is_valid():
            return Response(
                data=serializer.update(job_posting, validated_data=data), status=200
            )
        else:
            return Response(data={"errors": serializer.errors})


class GetSelectionContent(APIView):
    def get(self, request, *args, **kwargs):
        # position_name_list = []
        # Todo: #Imagine you will get list of selected positions(Position_names) for the job
        # queryset = SelectionProcessContent.objects.none()
        # for i in position_name_list:
        #     if SelectionProcessContent.objects.filter(description__icontains=i):
        #         queryset |= SelectionProcessContent.objects.filter(description__icontains=i)
        #
        # serializer = SelectionProcessContentSerializer(queryset,many=True)

        # For now sending all records
        process_content = SelectionProcessContent.objects.filter(is_deleted=False)
        serializer = SelectionProcessContentSerializer(process_content, many=True)
        return Response(serializer.data, status=200)


class GetServiceConditions(APIView):
    def get(self, request, *args, **kwargs):
        conditions = ServiceConditions.objects.filter(is_deleted=False)
        serializer = ServiceConditionsSerializer(conditions, many=True)
        return Response(serializer.data, status=200)


# Filtering on Position, Experience, Job Requirements, Status


class JobPostingSearchListView(ListAPIView):
    queryset = JobPosting.objects.filter(is_deleted=False)
    serializer_class = JobPostingSerializer
    filter_backends = [SearchFilter]
    search_fields = ("notification_id", "notification_title", "status")


class JobPostingFilterListView(ListAPIView):
    queryset = JobPosting.objects.filter(is_deleted=False)
    serializer_class = JobPostingSerializer
    filterset_fields = ["status"]


class JobPostingListView(ListAPIView):
    queryset = JobPosting.objects.prefetch_related("job_posting_applicants").filter(
        is_deleted=False
    )
    serializer_class = JobPostingSerializer
    filterset_fields = ["job_type", "status"]


class PublicJobPostingView(ListAPIView):
    permission_classes = (AllowAny,)
    serializer_class = PublicJobPostSerializer
    queryset = JobPosting.objects.filter(is_deleted=False)


class PublicJobPostingFilterListView(ListAPIView):
    permission_classes = (AllowAny,)
    queryset = JobPosting.objects.filter(is_deleted=False)
    serializer_class = PublicJobPostSerializer
    filterset_fields = ["description", "publication_date", "end_date"]


class PublicJobPostingSearchListView(ListAPIView):
    permission_classes = (AllowAny,)
    serializer_class = PublicJobPostSerializer
    queryset = JobPosting.objects.filter(is_deleted=False)
    filter_backends = [SearchFilter]
    search_fields = (
        "pre_ad_description",
        "post_ad_description",
    )


class ApplicantJobPositions(RetrieveAPIView):
    permission_classes = (AllowAny,)
    serializer_class = PublicJobPostSerializer
    queryset = JobPosting.objects.filter(is_deleted=False)
    lookup_field = "job_posting_id"
    lookup_url_kwarg = "id"


class ApplicationCountByJobPositions(APIView):
    def get(self, request, *args, **kwargs):
        job_posting_id = self.kwargs["id"]
        try:
            if UserJobPositions.objects.filter(
                job_posting__job_posting_id=job_posting_id, is_deleted=False
            ).exists():
                applicant_count = UserJobPositions.objects.filter(
                    job_posting__job_posting_id=job_posting_id, is_deleted=False
                ).count()
                print("applicants---------->", applicant_count)
                return Response(applicant_count, status=200)
            else:
                return Response(
                    data={"message": "No Application for this job..."},
                    status=200,
                )
        except:
            return Response(
                data={"message": "No Application for this job..."},
                status=200,
            )


class ApplicantListByJobPositions(APIView):
    def get(self, request, *args, **kwargs):
        try:
            job_posting_id = self.kwargs["id"]
            applicants = UserJobPositions.objects.prefetch_related(
                "user", "user__user_profile", "job_posting", "position"
            ).filter(job_posting__job_posting_id=job_posting_id, is_deleted=False)
            serializer = UserJobPositionsSerializer(applicants, many=True)
            return Response(serializer.data, status=200)
        except:
            applicants = UserJobPositions.objects.filter(is_deleted=False)
            serializer = UserJobPositionsSerializer(applicants, many=True)
            return Response(serializer.data, status=200)


class ApproveRejectApplicantView(RetrieveUpdateAPIView):
    queryset = UserJobPositions.objects.all()
    serializer_class = UserJobPositionsSerializer
    lookup_url_kwarg = "id"

    @atomic
    def put(self, request, *args, **kwargs):
        data = self.request.data
        application_id = self.kwargs["id"]
        print("data------------->", data)
        try:
            applicant = UserJobPositions.objects.get(id=application_id)
            # for status_data in data:
            print("status_data------------->", data["status"])
            print(
                "applicant.applied_job_status == data['status']------------->",
                applicant.applied_job_status,
                data["status"],
            )

            if data["status"] == "rejected" and applicant.applied_job_status:
                serializer = UserJobPositionsSerializer(applicant, data=data)
                serializer.is_valid(raise_exception=True)  # approve/reject/draft
                serializer.update(applicant, validated_data=data)
                return Response(serializer.data, status=200)
            elif data["status"] == "accepted" and applicant.applied_job_status:
                serializer = UserJobPositionsSerializer(applicant, data=data)
                serializer.is_valid(raise_exception=True)  # approve/reject/draft
                serializer.update(applicant, validated_data=data)
                return Response(serializer.data, status=200)
            elif data["status"] == "awaiting review" and applicant.applied_job_status:
                serializer = UserJobPositionsSerializer(applicant, data=data)
                serializer.is_valid(raise_exception=True)  # approve/reject/draft
                serializer.update(applicant, validated_data=data)
                return Response(serializer.data, status=200)
            else:
                return Response(
                    data={"message": "Please select a valid job status."},
                    status=200,
                )
        except:
            return Response(data={"message": "Detail not found"}, status=401)


class ApproveRejectApplicantForJobPositions(APIView):
    def put(self, request, *args, **kwargs):
        data = self.request.data
        appeal_id = self.kwargs["id"]
        try:
            applicants = UserJobPositions.objects.get(id=appeal_id)
            if applicants.applied_job_status == "rejected":
                applicants.appealed = True
                applicants.save()
                serializer = UserAppealForJobPositionsSerializer(applicants, data=data)
                serializer.is_valid(raise_exception=True)
                serializer.update(applicants, validated_data=data)
                return Response(serializer.data, status=200)
            else:
                return Response(
                    data={"message": "You've already appealed for this job..."},
                    status=200,
                )
        except:
            return Response(
                data={"message": "you are not eligible for the appeal..."}, status=401
            )


class UserAppealForJobPositions(APIView):
    def put(self, request, *args, **kwargs):
        data = self.request.data
        appeal_id = self.kwargs["id"]
        applicants = UserJobPositions.objects.get(id=appeal_id)
        if applicants.applied_job_status == "rejected":
            applicants.applied_job_status = "appealed"
            applicants.save()
            serializer = UserAppealForJobPositionsSerializer(applicants, data=data)
            serializer.is_valid(raise_exception=True)
            serializer.update(applicants, validated_data=data)
            return Response(serializer.data, status=200)
        if applicants.applied_job_status == "appealed":
            return Response(
                data={"message": "You've already appealed for this job..."},
                status=200,
            )
        else:
            return Response(
                data={"message": "you are not eligible for the appeal..."},
                status=200,
            )


class AppealReasonMasterViews(APIView):
    def post(self, request, *args, **kwargs):
        data = self.request.data
        serializer = AppealReasonMasterSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=200)

    def get(self, request, *args, **kwargs):
        try:
            appeal_id = self.kwargs["id"]
            applicant = AppealMaster.objects.get(appeal_id=appeal_id, is_deleted=False)
            serializer = AppealReasonMasterSerializer(applicant)
            return Response(serializer.data, status=200)
        except:
            applicants = AppealMaster.objects.filter(is_deleted=False)
            serializer = AppealReasonMasterSerializer(applicants, many=True)
            return Response(serializer.data, status=200)

    def delete(self, request, *args, **kwargs):
        try:
            appeal_id = self.kwargs["id"]
            applicant = AppealMaster.objects.get(appeal_id=appeal_id)
            applicant.is_deleted = True
            applicant.save()
            return Response(
                data={"message": "Record Deleted Successfully(Soft Delete)."},
                status=200,
            )
        except:
            return Response(data={"message": "Details Not Found."}, status=401)

    def put(self, request, *args, **kwargs):
        appeal_id = self.kwargs["id"]
        applicant = AppealMaster.objects.get(appeal_id=appeal_id)
        data = self.request.data
        serializer = AppealReasonMasterSerializer(applicant, data=data)
        serializer.is_valid(raise_exception=True)
        serializer.update(instance=applicant, validated_data=data)
        return Response(serializer.data, status=200)


# NewPositionMaster
class NewPositionMasterViews(APIView):
    def post(self, request, *args, **kwargs):
        data = self.request.data
        print("data ------->", data)
        serializer = NewPositionMasterSerializer(data=data)
        print("serializer ----------->", serializer)
        serializer.is_valid(raise_exception=True)
        result = serializer.save(validated_data=data)
        print("result ----------->", result)
        posi = NewPositionMaster.objects.get(position_id=result)
        serializer = NewPositionMasterSerializer(posi)
        return Response(serializer.data, status=200)

    def get(self, request, *args, **kwargs):
        try:
            position_id = self.kwargs["id"]
            if NewPositionMaster.objects.filter(
                position_id=position_id, is_deleted=False
            ).exists():
                position = NewPositionMaster.objects.get(
                    position_id=position_id, is_deleted=False
                )
                serializer = NewPositionMasterSerializer(position)
                return Response(serializer.data, status=200)
            else:
                return Response(data={"message": "Details Not Found."}, status=401)
        except:
            positions = NewPositionMaster.objects.filter(is_deleted=False)
            serializer = NewPositionMasterSerializer(positions, many=True)
            return Response(serializer.data, status=200)

    def put(self, request, *args, **kwargs):
        id = self.kwargs["id"]
        posi = NewPositionMaster.objects.get(position_id=id)
        data = self.request.data
        serializer = NewPositionMasterSerializer(posi, data=data)
        serializer.is_valid(raise_exception=True)
        serializer.update(instance=posi, validated_data=data)
        return Response(serializer.data, status=200)

    def delete(self, request, *args, **kwargs):
        try:
            id = self.kwargs["id"]
            posi = NewPositionMaster.objects.get(position_id=id)
            posi.is_deleted = True
            posi.save()
            return Response(
                data={
                    "message": "ManPower Position Deleted Successfully(Soft Delete)."
                },
                status=200,
            )
        except:
            return Response(data={"message": "Details Not Found."}, status=401)


# Permanent Position
class PermanentPositionMasterFilterListView(ListAPIView):
    queryset = PermanentPositionMaster.objects.all()
    serializer_class = PermanentPositionMasterSerializer
    filterset_fields = [
        "perm_position_master__position_name",
        "perm_position_master__position_display_name",
        "perm_position_master__qualification",
        "perm_position_master__qualification_job_history",
        "grade",
        "level",
    ]


class PermanentPositionMasterSearchListView(ListAPIView):
    queryset = PermanentPositionMaster.objects.all()
    serializer_class = PermanentPositionMasterSerializer
    filter_backends = [SearchFilter]
    search_fields = (
        "perm_position_master__qualification__qualification",
        "perm_position_master__qualification_desc",
    )


class PermanentPositionMasterViews(APIView):
    def get(self, request, *args, **kwargs):
        try:
            position_id = self.kwargs["id"]
            if PermanentPositionMaster.objects.filter(
                perm_position_id=position_id, is_deleted=False
            ).exists():
                position = PermanentPositionMaster.objects.get(
                    perm_position_id=position_id, is_deleted=False
                )
                serializer = PermanentPositionMasterSerializer(position)
                return Response(serializer.data, status=200)
            else:
                return Response(data={"message": "Details Not Found."}, status=401)
        except:
            positions = PermanentPositionMaster.objects.filter(is_deleted=False).order_by('perm_position_master__position_name')
            serializer = PermanentPositionMasterSerializer(positions, many=True)
            return Response(serializer.data, status=200)

    def delete(self, request, *args, **kwargs):
        try:
            id = self.kwargs["id"]
            info = PermanentPositionMaster.objects.get(perm_position_id=id)
            info.is_deleted = True
            info.save()
            return Response(
                data={
                    "message": "Permanent Position Deleted Successfully(Soft Delete)."
                },
                status=200,
            )
        except:
            return Response(data={"message": "Details Not Found."}, status=401)

    def put(self, request, *args, **kwargs):
        data = self.request.data
        id = self.kwargs["id"]
        try:
            info = PermanentPositionMaster.objects.get(
                perm_position_id=id, is_deleted=False
            )
            print("info ------->", info)

            serializer = PermanentPositionMasterSerializer(info, data=data)
            serializer.is_valid(raise_exception=True)
            result = serializer.update(instance=info, validated_data=data)
            print("result ------->", result)

            info = PermanentPositionMaster.objects.get(perm_position_id=result)
            print("info after------->", info)

            serializer = PermanentPositionMasterSerializer(info)
            print("serializer ------->", serializer.data)

            return Response(serializer.data, status=200)
        except Exception as e:
            return Response(data={"errors": str(e)})

    def post(self, request, *args, **kwargs):
        try:
            data = self.request.data
            print("data ------->", data)
            serializer = PermanentPositionMasterSerializer(data=data)
            print("serializer ----------->", serializer)
            serializer.is_valid(raise_exception=True)
            result = serializer.save(validated_data=data)
            print("result ----------->", result)
            posi = PermanentPositionMaster.objects.get(perm_position_id=result)
            serializer = PermanentPositionMasterSerializer(posi)
            return Response(serializer.data, status=200)
        except Exception as e:
            return Response(data={"errors": str(e)})


# Temporary Position
class TemporaryPositionMasterFilterListView(ListAPIView):
    queryset = TemporaryPositionMaster.objects.filter(is_deleted=False)
    serializer_class = TemporaryPositionMasterSerializer
    filterset_fields = [
        "temp_position_master__position_name",
        "temp_position_master__position_display_name",
        "temp_position_master__qualification",
        "temp_position_master__qualification_job_history",
        "salary",
        "allowance",
    ]


class TemporaryPositionMasterSearchListView(ListAPIView):
    queryset = TemporaryPositionMaster.objects.filter(is_deleted=False)
    serializer_class = TemporaryPositionMasterSerializer
    filter_backends = [SearchFilter]
    search_fields = (
        "temp_position_master__qualification__qualification",
        "temp_position_master__qualification_desc",
    )


class TemporaryPositionMasterViews(APIView):
    def get(self, request, *args, **kwargs):
        try:
            position_id = self.kwargs["id"]
            if TemporaryPositionMaster.objects.filter(
                temp_position_id=position_id, is_deleted=False
            ).exists():
                position = TemporaryPositionMaster.objects.get(
                    temp_position_id=position_id, is_deleted=False
                )
                serializer = TemporaryPositionMasterSerializer(position)
                return Response(serializer.data, status=200)
            else:
                return Response(data={"message": "Details Not Found."}, status=401)
        except:
            positions = TemporaryPositionMaster.objects.filter(is_deleted=False).order_by('temp_position_master__position_name')
            serializer = TemporaryPositionMasterSerializer(positions, many=True)
            return Response(serializer.data, status=200)

    def delete(self, request, *args, **kwargs):
        try:
            id = self.kwargs["id"]
            info = TemporaryPositionMaster.objects.get(temp_position_id=id)
            info.is_deleted = True
            info.save()
            return Response(
                data={
                    "message": "Temporary Position Deleted Successfully(Soft Delete)."
                },
                status=200,
            )
        except:
            return Response(data={"message": "Details Not Found."}, status=401)

    def put(self, request, *args, **kwargs):
        data = self.request.data
        id = self.kwargs["id"]
        try:
            info = TemporaryPositionMaster.objects.get(
                temp_position_id=id, is_deleted=False
            )
            print("info ------->", info)
            serializer = TemporaryPositionMasterSerializer(info, data=data)
            serializer.is_valid(raise_exception=True)
            result = serializer.update(instance=info, validated_data=data)
            print("result ------->", result)
            info = TemporaryPositionMaster.objects.get(temp_position_id=result)
            print("info after------->", info)

            serializer = TemporaryPositionMasterSerializer(info)
            print("serializer ------->", serializer.data)

            return Response(serializer.data, status=200)
        except Exception as e:
            return Response(data={"errors": str(e)})

    def post(self, request, *args, **kwargs):
        try:
            data = self.request.data
            print("data ------->", data)
            serializer = TemporaryPositionMasterSerializer(data=data)
            print("serializer ----------->", serializer)
            serializer.is_valid(raise_exception=True)
            result = serializer.save(validated_data=data)
            print("result ----------->", result)
            posi = TemporaryPositionMaster.objects.get(temp_position_id=result)
            serializer = TemporaryPositionMasterSerializer(posi)
            return Response(serializer.data, status=200)
        except Exception as e:
            return Response(data={"errors": str(e)})


