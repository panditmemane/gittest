from job_posting.models import (
    JobPostingRequirementPositions,
    AppealMaster,
    NewPositionMaster,
    PermanentPositionMaster,
    TemporaryPositionMaster,
    QualificationJobHistoryMaster,
)
from rest_framework import serializers
from job_posting.models import (
    UserJobPositions,
    Department,
    Division,
    ZonalLab,
    QualificationMaster,
    PositionQualificationMapping,
    JobPostingRequirement,
    JobTemplate,
    JobDocuments,
    JobPosting,
    SelectionProcessContent,
    SelectionCommitteeMaster,
    ServiceConditions,
)
from document.serializer import InformationMasterSerializer, NewDocumentMasterSerializer
from document.models import NewDocumentMaster, InformationMaster
from user.serializer import UserProfilePreviewSerializer


class ApplicantJobPositionsSerializer(serializers.ModelSerializer):
    notification_id = serializers.CharField(source="job_posting.notification_id")
    description = serializers.SerializerMethodField(
        method_name="get_description", read_only=True
    )

    class Meta:
        model = UserJobPositions
        fields = (
            "id",
            "notification_id",
            "description",
            "date_of_application",
            "date_of_closing",
            "hiring_status",
            "user_job_position_id",
        )

    def get_description(self, obj):
        description = (
            obj.position.position.position_name or obj.position.position_display_name
        )
        return description


class DepartmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Department
        fields = (
            "dept_id",
            "dept_name",
        )


class DivisionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Division
        fields = (
            "division_id",
            "division_name",
        )


class ZonalLabSerializer(serializers.ModelSerializer):
    class Meta:
        model = ZonalLab
        fields = (
            "zonal_lab_id",
            "zonal_lab_name",
        )


class QualificationMasterSerializer(serializers.ModelSerializer):
    class Meta:
        model = QualificationMaster
        fields = (
            "qualification_id",
            "qualification",
            "short_code",
        )


class QualificationJobHistoryMasterSerializer(serializers.ModelSerializer):
    class Meta:
        model = QualificationJobHistoryMaster
        fields = (
            "qualification_job_id",
            "qualification",
            "short_code",
        )


class AdminPositionQualificationMappingSerializer(serializers.ModelSerializer):
    position_id = serializers.UUIDField(source="position.position_id", required=False)
    position = serializers.CharField(
        source="position.position_display_name", read_only=True
    )
    qualification = serializers.SerializerMethodField()
    documents_required = serializers.SerializerMethodField()
    information_required = serializers.SerializerMethodField()
    qualification_job_history = serializers.SerializerMethodField()

    class Meta:
        model = PositionQualificationMapping
        fields = (
            "id",
            "position_id",
            "position",
            "qualification",
            "documents_required",
            "information_required",
            "qualification_job_history",
            "min_age",
            "max_age",
            "number_of_vacancies",
            "monthly_emolements",
            "allowance",
            "extra_note",
            "grade",
            "level",
        )

    def get_qualification(self, obj):
        return obj.qualification.all().values_list("qualification_id", flat=True)

    def get_documents_required(self, obj):
        return obj.documents_required.all().values_list("doc_id", flat=True)

    def get_information_required(self, obj):
        return obj.information_required.all().values_list("info_id", flat=True)

    def get_qualification_job_history(self, obj):
        return obj.qualification_job_history.all().values_list(
            "qualification_job_id", flat=True
        )


class PositionQualificationMappingSerializer(serializers.ModelSerializer):
    position_id = serializers.UUIDField(source="position.position_id", required=False)
    position = serializers.CharField(
        source="position.position_display_name", read_only=True
    )
    qualification = QualificationMasterSerializer(many=True, read_only=True)
    qualification_job_history = QualificationJobHistoryMasterSerializer(
        many=True, read_only=True
    )
    information_required = InformationMasterSerializer(many=True, read_only=True)
    documents_required = NewDocumentMasterSerializer(many=True, read_only=True)

    class Meta:
        model = PositionQualificationMapping
        fields = (
            "id",
            "position_id",
            "position",
            "qualification",
            "qualification_job_history",
            "information_required",
            "documents_required",
            "min_age",
            "max_age",
            "number_of_vacancies",
            "monthly_emolements",
            "allowance",
            "extra_note",
            "grade",
            "level",
        )


class JobPostingRequirementPositionsSerializer(serializers.ModelSerializer):
    salary = serializers.FloatField(source="position.salary", read_only=True)

    class Meta:
        model = JobPostingRequirementPositions

        fields = (
            "id",
            "position",
            "job_posting_requirement",
            "salary",
            "count",
            "total_cost",
        )

class ProjectApprovalListSerializer(serializers.ModelSerializer):
    project_number = serializers.SerializerMethodField(
        method_name="get_project_number", read_only=True
    )

    class Meta:
        model = JobPostingRequirement
        fields = ("project_number",)

    def get_project_number(self, obj):
        return obj.project_number


class ProjectRequirementApprovalStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = JobPostingRequirement
        fields = (
            "id",
            "status",
        )

    def update(self, instance, validated_data):
        instance.status = (
            validated_data["status"] if validated_data["status"] else instance.status
        )

        instance.save()

        return instance.id


class ProjectRequirementSerializer(serializers.ModelSerializer):
    division_name = serializers.SerializerMethodField(
        method_name="get_division_name", required=False
    )

    zonal_lab = serializers.SerializerMethodField(
        method_name="get_zonal_lab", required=False
    )

    # manpower_positions = serializers.SerializerMethodField(
    #     method_name='get_manpower_positions', required=False
    # )

    project_number = serializers.SerializerMethodField(
        method_name="get_project_number", read_only=True
    )
    manpower_position = JobPostingRequirementPositionsSerializer(many=True)

    class Meta:
        model = JobPostingRequirement

        fields = (
            "id",
            "division_name",
            "zonal_lab",
            "project_title",
            "is_deleted",
            "project_number",
            "project_start_date",
            "project_end_date",
            "manpower_position",
            "provisions_made",
            "total_estimated_amount",
            "min_essential_qualification",
            "job_requirements",
            "desired_qualification",
            "status",
        )
        extra_kwargs = {"position": {"required": False}}

    def get_project_number(self, obj):
        return obj.project_number

    def get_division_name(self, obj):
        division = obj.division_name
        serializer = DivisionSerializer(division)
        return serializer.data

    def get_zonal_lab(self, obj):
        zonal_lab = obj.zonal_lab
        serializer = ZonalLabSerializer(zonal_lab)
        return serializer.data

    def get_manpower_positions(self, obj):
        positions = obj.manpower_positions.filter()
        serializer = TemporaryPositionMasterSerializer(positions, many=True)
        return serializer.data

    def save(self, validated_data):

        requi = JobPostingRequirement.objects.create(
            project_title=validated_data["project_title"],
            project_number=validated_data["project_number"],
            project_start_date=validated_data["project_start_date"],
            project_end_date=validated_data["project_end_date"],
            provisions_made=validated_data["provisions_made"],
            total_estimated_amount=validated_data["total_estimated_amount"],
            min_essential_qualification=validated_data["min_essential_qualification"],
            job_requirements=validated_data["job_requirements"],
            desired_qualification=validated_data["desired_qualification"],
            status=validated_data["status"],
        )

        division_name = Division.objects.get(
            division_id=validated_data["division_name"]["division_id"]
        )
        zonal_lab = ZonalLab.objects.get(
            zonal_lab_id=validated_data["zonal_lab"]["zonal_lab_id"]
        )
        requi.division_name = division_name
        requi.zonal_lab = zonal_lab
        requi.save()

        for position_data in validated_data["manpower_position"]:
            print("hello position_data ******************************", position_data)
            manpower_position = TemporaryPositionMaster.objects.get(
                temp_position_id=position_data["position"]
            )
            count = position_data["count"]
            total_cost = position_data["total_cost"]
            JobPostingRequirementPositions.objects.create(
                position=manpower_position,
                job_posting_requirement=requi,
                count=count,
                total_cost=total_cost,
            )
            requi.manpower_positions.add(manpower_position)
        return requi.id

    def update(self, instance, validated_data):
        print("instance \n", instance)
        print("validated_data\n", validated_data)
        if instance:
            instance.project_title = (
                validated_data["project_title"]
                if validated_data["project_title"]
                else instance.project_title
            )
            instance.project_number = (
                validated_data["project_number"]
                if validated_data["project_number"]
                else instance.project_number
            )
            instance.project_start_date = (
                validated_data["project_start_date"]
                if validated_data["project_start_date"]
                else instance.project_start_date
            )
            instance.project_end_date = (
                validated_data["project_end_date"]
                if validated_data["project_end_date"]
                else instance.project_end_date
            )
            instance.provisions_made = (
                validated_data["provisions_made"]
                if validated_data["provisions_made"]
                else instance.provisions_made
            )
            instance.total_estimated_amount = (
                validated_data["total_estimated_amount"]
                if validated_data["total_estimated_amount"]
                else instance.total_estimated_amount
            )
            instance.min_essential_qualification = (
                validated_data["min_essential_qualification"]
                if validated_data["min_essential_qualification"]
                else instance.min_essential_qualification
            )
            instance.job_requirements = (
                validated_data["job_requirements"]
                if validated_data["job_requirements"]
                else instance.job_requirements
            )
            instance.desired_qualification = (
                validated_data["desired_qualification"]
                if validated_data["desired_qualification"]
                else instance.desired_qualification
            )
            instance.status = (
                validated_data["status"]
                if validated_data["status"]
                else instance.status
            )
            instance.is_deleted = (
                validated_data["is_deleted"]
                if validated_data["is_deleted"]
                else instance.is_deleted
            )

            division_name = validated_data["division_name"]["division_name"]
            zonal_lab = validated_data["zonal_lab"]["zonal_lab_name"]
            division = Division.objects.filter(division_name__exact=division_name).first()
            zonal = ZonalLab.objects.filter(zonal_lab_name__exact=zonal_lab).first()
            if instance.division_name == division:
                pass
            else:
                instance.department = division

            if instance.zonal_lab == zonal:
                pass
            else:
                instance.division = zonal

            instance.save()
            posi = instance.manpower_position.filter()
            # print(
            #     "validated_data['perm_position_master']['qualification']---------->",
            #     validated_data["perm_position_master"]["qualification"],
            # )
            if not validated_data["manpower_position"]:  # working for empty position.
                for oposi in posi:
                    instance.manpower_position.remove(oposi)
                    print("posi deleted")
            for oposi in posi:
                for posi_data in validated_data["manpower_position"]: # working for single position deletion.
                    if str(oposi.id) != str(
                            posi_data["id"]
                    ):
                        instance.manpower_position.remove(oposi)
            for position_data in validated_data["manpower_position"]:
                manpower_position = TemporaryPositionMaster.objects.get(
                    temp_position_id=position_data["position"]
                )
                try:
                    inst = JobPostingRequirementPositions.objects.get(
                        id=position_data["id"]
                    )
                    inst.count = position_data["count"]
                    inst.position = manpower_position
                    manpower_position.salary = position_data["salary"]
                    inst.job_posting_requirement = instance
                    inst.total_cost = position_data["total_cost"]
                    inst.save()
                    manpower_position.save()
                except:
                    JobPostingRequirementPositions.objects.create(
                        position=manpower_position,
                        job_posting_requirement=instance,
                        count=position_data["count"],
                        total_cost=position_data["total_cost"],
                    )
                    instance.manpower_positions.add(manpower_position)
        return instance.id


class JobTemplateSerializer(serializers.ModelSerializer):
    position = serializers.SerializerMethodField(
        method_name="get_position", read_only=True
    )

    qualification = serializers.SerializerMethodField(
        method_name="get_qualification", read_only=True
    )

    class Meta:
        model = JobTemplate
        fields = (
            "template_name",
            "position",
            "qualification",
            "min_age",
            "max_age",
            "number_of_vacancies",
            "monthly_emolements",
            "allowance",
            "extra_note",
        )

    def get_position(self, obj):
        serializer = NewPositionMasterSerializer(obj.position)
        return serializer.data

    def get_qualification(self, obj):
        qualifications = obj.qualification.filter()
        serializer = QualificationMasterSerializer(qualifications, many=True)
        return serializer.data

    def save(self, validated_data):
        template = JobTemplate.objects.create(
            template_name=validated_data["template_name"],
            min_age=validated_data["min_age"],
            max_age=validated_data["max_age"],
            number_of_vacancies=validated_data["number_of_vacancies"],
            monthly_emolements=validated_data["monthly_emolements"],
            allowance=validated_data["allowance"],
            extra_note=validated_data["extra_note"],
        )

        position = NewPositionMaster.objects.get(
            position_id=validated_data["position"]["position_id"]
        )
        template.position = position
        template.save()

        for qualification_data in validated_data["qualification"]:
            qualification = QualificationMaster.objects.get(
                qualification_id=qualification_data["qualification_id"]
            )
            template.qualification.add(qualification)


class JobDocumentsSerializer(serializers.ModelSerializer):
    class Meta:
        model = JobDocuments
        fields = (
            "doc_id",
            "doc_file_path",
            "doc_name",
        )


class PublicJobPostSerializer(serializers.ModelSerializer):
    manpower_positions = serializers.SerializerMethodField(
        method_name="get_manpower_positions", required=False
    )
    division = serializers.SerializerMethodField(
        method_name="get_division", read_only=True, required=False
    )
    zonal_lab = serializers.SerializerMethodField(
        method_name="get_zonal_lab", read_only=True, required=False
    )
    documents_required = serializers.SerializerMethodField(
        method_name="get_documents_required", required=False
    )

    class Meta:
        model = JobPosting
        fields = (
            "job_posting_id",
            "pre_ad_description",
            "post_ad_description",
            "notification_id",
            "notification_title",
            "ad_approval_id",
            "publication_date",
            "end_date",
            "job_type",
            "manpower_positions",
            "division",
            "zonal_lab",
            "status",
            "job_type",
            "documents_required",
        )

    def get_manpower_positions(self, obj):
        positions = obj.manpower_positions.filter()
        serializer = PositionQualificationMappingSerializer(positions, many=True)
        return serializer.data

    def get_division(self, obj):
        division = obj.division
        serializer = DivisionSerializer(division)
        return serializer.data

    def get_zonal_lab(self, obj):
        zonal_lab = obj.zonal_lab
        serializer = ZonalLabSerializer(zonal_lab)
        return serializer.data

    def get_documents_required(self, obj):
        documents_required = obj.documents_required.filter()
        serializer = NewDocumentMasterSerializer(documents_required, many=True)
        return serializer.data


class JobPostingSerializer(serializers.ModelSerializer):
    manpower_positions = serializers.SerializerMethodField(
        method_name="get_manpower_positions", required=False
    )
    division_id = serializers.UUIDField(required=False)
    zonal_lab_id = serializers.UUIDField(required=False)
    office_memorandum = serializers.SerializerMethodField(
        method_name="get_office_memorandum", required=False
    )
    documents_required = serializers.SerializerMethodField(
        method_name="get_documents_required", required=False
    )
    documents_uploaded = serializers.SerializerMethodField(
        method_name="get_documents_uploaded", required=False
    )
    applied_applicants = serializers.SerializerMethodField(
        method_name="get_applied_applicants", required=False, read_only=True
    )
    is_deleted = serializers.BooleanField(default=False, write_only=True)

    class Meta:
        model = JobPosting
        fields = (
            "job_posting_id",
            "notification_id",
            "notification_title",
            "ad_approval_id",
            "pre_ad_description",
            "post_ad_description",
            "division_id",
            "zonal_lab_id",
            "applied_applicants",
            "publication_date",
            "end_date",
            "documents_required",
            "documents_uploaded",
            "office_memorandum",
            "status",
            "job_type",
            "manpower_positions",
            "is_deleted",
        )

    def get_applied_applicants(self, obj):
        return len(obj.job_posting_applicants.all())

    def get_manpower_positions(self, obj):
        positions = obj.manpower_positions.filter()
        serializer = AdminPositionQualificationMappingSerializer(positions, many=True)
        return serializer.data

    def get_documents_required(self, obj):
        documents_required = obj.documents_required.filter()
        return documents_required.values_list("doc_id", flat=True)

    def get_documents_uploaded(self, obj):
        documents_uploaded = obj.documents_uploaded.filter()
        serializer = JobDocumentsSerializer(documents_uploaded, many=True)
        return serializer.data

    def get_office_memorandum(self, obj):
        office_memorandum = obj.office_memorandum
        serializer = JobDocumentsSerializer(office_memorandum)
        return serializer.data

    def update(self, instance, validated_data):
        instance.notification_id = (
            validated_data.get("notification_id") or instance.notification_id
        )
        instance.notification_title = (
            validated_data.get("notification_title") or instance.notification_title
        )
        instance.ad_approval_id = (
            validated_data.get("ad_approval_id") or instance.ad_approval_id
        )
        instance.pre_ad_description = (
            validated_data.get("pre_ad_description") or instance.pre_ad_description
        )
        instance.post_ad_description = (
            validated_data.get("post_ad_description") or instance.post_ad_description
        )
        instance.publication_date = (
            validated_data.get("publication_date") or instance.publication_date
        )
        instance.end_date = validated_data.get("end_date") or instance.end_date
        instance.status = validated_data.get("status") or instance.status
        instance.job_type = validated_data.get("job_type") or instance.job_type
        instance.division_id = validated_data.get("division_id") or instance.division_id
        instance.zonal_lab_id = (
            validated_data.get("zonal_lab_id") or instance.zonal_lab_id
        )
        if validated_data.get("documents_uploaded"):
            instance.documents_uploaded.clear()
            for document in validated_data["documents_uploaded"]:
                job_doc = JobDocuments.objects.get(doc_id=document)
                instance.documents_uploaded.add(job_doc)

        if validated_data.get("manpower_positions"):
            instance.manpower_positions.clear()
            for position_mapping in validated_data["manpower_positions"]:
                position = NewPositionMaster.objects.get(
                    position_id=position_mapping["position_id"]
                )
                position_qualification_mapping = (
                    PositionQualificationMapping.objects.create(
                        position=position,
                        position_display_name=position_mapping["position"],
                        min_age=position_mapping.get("min_age"),
                        max_age=position_mapping.get("max_age"),
                        monthly_emolements=position_mapping.get("monthly_emolements"),
                        allowance=position_mapping["allowance"],
                        extra_note=position_mapping["extra_note"],
                        number_of_vacancies=position_mapping["number_of_vacancies"],
                        grade=position_mapping.get("grade"),
                        level=position_mapping.get("level"),
                    )
                )

                for qualification in position_mapping["qualification"]:
                    qualification_obj = QualificationMaster.objects.get(
                        qualification_id=qualification
                    )
                    position_qualification_mapping.qualification.add(qualification_obj)

                for information in position_mapping["information_required"]:
                    information_obj = InformationMaster.objects.get(info_id=information)
                    position_qualification_mapping.information_required.add(
                        information_obj
                    )

                for doc_id in position_mapping["documents_required"]:
                    document = NewDocumentMaster.objects.get(doc_id=doc_id)
                    position_qualification_mapping.documents_required.add(document)

                for qualification_history_id in position_mapping[
                    "qualification_job_history"
                ]:
                    qualification_history = QualificationJobHistoryMaster.objects.get(
                        qualification_job_id=qualification_history_id
                    )
                    position_qualification_mapping.qualification_job_history.add(
                        qualification_history
                    )

                instance.manpower_positions.add(position_qualification_mapping)

        if validated_data.get("is_deleted") is not None:
            instance.is_deleted = validated_data["is_deleted"]
        """
        project_number = JobPostingRequirement.objects.get(
            project_number__icontains=validated_data["project_number"]
        )
        instance.project_number = validated_data["project_number"] or instance.project_number
        """
        instance.save()
        return validated_data

    def save(self, validated_data):
        posting = JobPosting.objects.create(
            notification_id=validated_data["notification_id"],
            notification_title=validated_data["notification_title"],
            pre_ad_description=validated_data["pre_ad_description"],
            post_ad_description=validated_data["post_ad_description"],
            publication_date=validated_data["publication_date"],
            end_date=validated_data["end_date"],
            status=JobPosting.SCHEDULED,
            job_type=validated_data["job_type"],
            ad_approval_id=validated_data.get("ad_approval_id"),
        )

        for position_mapping in validated_data["manpower_positions"]:
            position = NewPositionMaster.objects.get(
                position_id=position_mapping["position_id"]
            )
            position_qualification_mapping = (
                PositionQualificationMapping.objects.create(
                    position=position,
                    min_age=position_mapping.get("min_age"),
                    max_age=position_mapping.get("max_age"),
                    monthly_emolements=position_mapping.get("monthly_emolements"),
                    allowance=position_mapping["allowance"],
                    extra_note=position_mapping["extra_note"],
                    number_of_vacancies=position_mapping["number_of_vacancies"],
                    grade=position_mapping.get("grade"),
                    level=position_mapping.get("level"),
                )
            )

            for qualification in position_mapping["qualification"]:
                qualification_obj = QualificationMaster.objects.get(
                    qualification_id=qualification
                )
                position_qualification_mapping.qualification.add(qualification_obj)

            for information in position_mapping["information_required"]:
                information_obj = InformationMaster.objects.get(info_id=information)
                position_qualification_mapping.information_required.add(information_obj)

            for doc_id in position_mapping["documents_required"]:
                document_required = NewDocumentMaster.objects.get(doc_id=doc_id)
                position_qualification_mapping.documents_required.add(document_required)

            for qualification_history_id in position_mapping[
                "qualification_job_history"
            ]:
                qualification_history = QualificationJobHistoryMaster.objects.get(
                    qualification_job_id=qualification_history_id
                )
                position_qualification_mapping.qualification_job_history.add(
                    qualification_history
                )

            posting.manpower_positions.add(position_qualification_mapping)

        for documents_required_data in validated_data["documents_required"]:
            document_required = NewDocumentMaster.objects.get(
                doc_id=documents_required_data
            )
            posting.documents_required.add(document_required)

        for document_uploaded in validated_data["documents_uploaded"]:
            job_doc = JobDocuments.objects.get(doc_id=document_uploaded)
            posting.documents_uploaded.add(job_doc)

        """
        project_number = JobPostingRequirement.objects.get(
            id=validated_data["project_number"]
        )
        posting.project_number = project_number
        """
        posting.division_id = validated_data["division_id"]
        posting.zonal_lab_id = validated_data["zonal_lab_id"]
        posting.save()
        return posting.job_posting_id


class SelectionCommitteeSerializer(serializers.ModelSerializer):
    class Meta:
        model = SelectionCommitteeMaster
        fields = (
            # "committee_id",
            "committee_name",
        )


class SelectionProcessContentSerializer(serializers.ModelSerializer):
    selection_committee = serializers.SerializerMethodField(
        method_name="get_selection_committee", required=False
    )

    class Meta:
        model = SelectionProcessContent
        fields = (
            "description",
            "selection_committee",
        )

    def get_selection_committee(self, obj):
        selection_committee = obj.selection_committee
        serializer = SelectionCommitteeSerializer(selection_committee, many=True)
        return serializer.data


class ServiceConditionsSerializer(serializers.ModelSerializer):
    class Meta:
        model = ServiceConditions
        fields = (
            "id",
            "title",
            "descriprtion",
        )


# class UserJobPositionsSerializer(serializers.ModelSerializer):
#     name = serializers.SerializerMethodField(method_name="get_name", required=False)
#
#     user_id = serializers.SerializerMethodField(
#         method_name="get_user_id", required=False
#     )
#     profile_photo = serializers.SerializerMethodField(
#         method_name="get_user_photo", required=False
#     )
#     department = serializers.SerializerMethodField(
#         method_name="get_department", required=False
#     )
#
#     status = serializers.SerializerMethodField(method_name="get_status", required=False)
#
#     position = serializers.SerializerMethodField(
#         method_name="get_position", required=False
#     )
#     date_applied = serializers.SerializerMethodField(
#         method_name="get_date_applied", required=False
#     )
#
#     contact = serializers.SerializerMethodField(
#         method_name="get_contact", required=False
#     )
#
#     class Meta:
#         model = UserJobPositions
#         fields = (
#             "user_id",
#             "profile_photo",
#             "name",
#             "department",
#             "status",
#             "position",
#             "date_applied",
#             "contact",
#         )
#
#     def get_name(self, obj):
#         first_name = obj.user.first_name if obj.user.first_name else None
#         middle_name = obj.user.middle_name if obj.user.middle_name else None
#         last_name = obj.user.last_name if obj.user.last_name else None
#         return first_name + " " + middle_name + " " + last_name
#
#     def get_user_id(self, obj):
#         return obj.user.user_id
#
#     def get_user_photo(self, obj):
#         profile = UserProfile.objects.get(user__user_id=obj.user.user_id)
#         user_profile = profile.profile_photo
#         return user_profile
#
#     def get_department(self, obj):
#         return obj.job_posting.department.dept_name
#
#     def get_status(self, obj):
#         return obj.applied_job_status
#
#     def get_position(self, obj):
#         return obj.position.position.position_name
#
#     def get_date_applied(self, obj):
#         return obj.date_of_application
#
#     def get_contact(self, obj):
#         return obj.user.mobile_no


class ApplicationCountForJobPositionSerializer(serializers.ModelSerializer):
    count = serializers.SerializerMethodField(
        method_name="get_application_id", required=False
    )

    class Meta:
        model = UserJobPositions
        fields = ("count",)

    def get_application_id(self, obj):
        return obj.id


class UserJobPositionsSerializer(serializers.ModelSerializer):
    user_id = serializers.UUIDField(source="user.user_id")
    user_profile = UserProfilePreviewSerializer(source="user.user_profile")
    division = serializers.CharField(source="job_posting.division.division_name")
    position = serializers.CharField(source="position.position_display_name")
    job_posting_id = serializers.UUIDField(source="job_posting.job_posting_id")
    application_id = serializers.IntegerField(source="id")

    class Meta:
        model = UserJobPositions
        fields = (
            "user_id",
            "user_profile",
            "application_id",
            "division",
            "applied_job_status",
            "job_posting_id",
            "position",
            "date_of_application",
        )

    def update(self, instance, validated_data):
        instance.applied_job_status = (
            validated_data.get("applied_job_status") or instance.applied_job_status
        )
        instance.save()
        return instance.id


class AppealReasonMasterSerializer(serializers.ModelSerializer):
    class Meta:
        model = AppealMaster
        fields = (
            "appeal_id",
            "appeal_reason_master",
        )


class UserAppealForJobPositionsSerializer(serializers.ModelSerializer):
    appeal = serializers.UUIDField(source="appeal.appeal_id")

    class Meta:
        model = UserJobPositions
        fields = (
            "id",
            "appeal",
            "reason_to_appeal",
        )

    def update(self, instance, validated_data):
        if instance:
            instance.reason_to_appeal = (
                validated_data.get("reason_to_appeal") or instance.reason_to_appeal
            )
            appeal_id = validated_data["appeal"]
            appeal = AppealMaster.objects.filter(appeal_id=appeal_id).first()
            if appeal:
                instance.appeal = appeal
            instance.save()

        return instance.id


class PermanentPositionMasterSerializer(serializers.ModelSerializer):
    perm_position_master = serializers.SerializerMethodField(
        method_name="get_position", read_only=True
    )

    # position_id = serializers.SerializerMethodField(
    #     method_name="get_position_id", read_only=True
    # )
    class Meta:
        model = PermanentPositionMaster
        fields = (
            "perm_position_id",
            # "position_id",
            "perm_position_master",
            "grade",
            "level",
        )

    def get_position(self, obj):
        serializer = NewPositionMasterSerializer(obj.perm_position_master)
        return serializer.data

    # def get_position_id(self, obj):
    #     return obj.perm_position.position_id

    def save(self, validated_data):
        posi = NewPositionMaster.objects.create(
            position_name=validated_data["perm_position_master"]["position_name"]
            if "position_name" in validated_data["perm_position_master"]
            else None,
            position_display_name=validated_data["perm_position_master"][
                "position_display_name"
            ],
            min_age=validated_data["perm_position_master"]["min_age"]
            if "min_age" in validated_data["perm_position_master"]
            else None,
            max_age=validated_data["perm_position_master"]["max_age"]
            if "max_age" in validated_data["perm_position_master"]
            else None,
            qualification_desc=validated_data["perm_position_master"][
                "qualification_desc"
            ]
            if "qualification_desc" in validated_data["perm_position_master"]
            else None,
        )
        print("validated_data--------->", validated_data)

        qualification = (
            validated_data["perm_position_master"]["qualification"]
            if "qualification" in validated_data["perm_position_master"]
            else None
        )

        print("qualification--------->", qualification)
        if qualification:

            for qualification_data in qualification:
                qualification = QualificationMaster.objects.get(
                    qualification_id=qualification_data["qualification_id"]
                )
                posi.qualification.add(qualification)
            print(
                "validated_data['qualification_job_history']--------->",
                validated_data["perm_position_master"]["qualification_job_history"],
            )

        qualification_hist = (
            validated_data["perm_position_master"]["qualification_job_history"]
            if "qualification_job_history" in validated_data["perm_position_master"]
            else None
        )

        print("qualification_hist #####--------->", qualification_hist)
        if qualification_hist:
            for exp in qualification_hist:
                print("exp--------->", exp)
                emp_exp = QualificationJobHistoryMaster.objects.get(
                    qualification_job_id=exp["qualification_job_id"]
                )
                posi.qualification_job_history.add(emp_exp)

        information = (
            validated_data["perm_position_master"]["information_required"]
            if "information_required" in validated_data["perm_position_master"]
            else None
        )

        print("information--------->", information)
        if information:
            for info_data in information:
                info = InformationMaster.objects.get(info_id=info_data["info_id"])
                posi.information_required.add(info)

        document = (
            validated_data["perm_position_master"]["documents_required"]
            if "documents_required" in validated_data["perm_position_master"]
            else None
        )

        print("document--------->", document)
        if document:
            for doc in document:
                docs = NewDocumentMaster.objects.get(doc_id=doc["doc_id"])
                posi.documents_required.add(docs)

        # posi_id = NewPositionMaster.objects.get(
        #     position_name=validated_data["perm_position_master"]["position_name"]
        # )
        # print("posi_id------>", posi_id)

        posi = PermanentPositionMaster.objects.create(
            perm_position_master=posi,
            grade=validated_data.get("grade"),
            level=validated_data.get("level"),
        )
        print("Done")

        return posi.perm_position_id

    def update(self, instance, validated_data):
        print("instance ----->", instance)
        print("validated_data ---->", validated_data)
        if instance:
            instance.grade = (
                validated_data["grade"] if validated_data["grade"] else instance.grade
            )
            instance.level = (
                validated_data["level"] if validated_data["level"] else instance.level
            )
            # instance.save()
            print(instance.perm_position_master.position_name)
            print(
                "validated_data['perm_position_master']['position_name']------------>",
                validated_data["perm_position_master"]["position_name"],
            )
            instance.perm_position_master.position_name = (
                validated_data["perm_position_master"]["position_name"]
                if validated_data["perm_position_master"]["position_name"]
                else instance.perm_position_master.position_name
            )

            instance.perm_position_master.position_display_name = (
                validated_data["perm_position_master"]["position_display_name"]
                if validated_data["perm_position_master"]["position_display_name"]
                else instance.perm_position_master.position_display_name
            )

            instance.perm_position_master.min_age = (
                validated_data["perm_position_master"]["min_age"]
                if validated_data["perm_position_master"]["min_age"]
                else instance.perm_position_master.min_age
            )

            instance.perm_position_master.max_age = (
                validated_data["perm_position_master"]["max_age"]
                if validated_data["perm_position_master"]["max_age"]
                else instance.perm_position_master.max_age
            )
            instance.perm_position_master.qualification_desc = (
                validated_data["perm_position_master"]["qualification_desc"]
                if validated_data["perm_position_master"]["qualification_desc"]
                else instance.perm_position_master.qualification_desc
            )
            instance.perm_position_master.save()
            instance.save()
        posi = NewPositionMaster.objects.get(
            position_id=validated_data["perm_position_master"]["position_id"]
        )
        oldqual = posi.qualification.filter()
        oldexp = posi.qualification_job_history.filter()
        olddoc = posi.documents_required.filter()
        oldinfo = posi.information_required.filter()
        # print(
        #     "validated_data['perm_position_master']['qualification']---------->",
        #     validated_data["perm_position_master"]["qualification"],
        # )
        if not validated_data["perm_position_master"][
            "qualification"
        ]:  # working for empty role.
            for oqual in oldqual:
                instance.perm_position_master.qualification.remove(oqual)
                # print("qual deleted")

        for oqual in oldqual:
            for qual_data in validated_data["perm_position_master"]["qualification"]:
                # print("qual_data.id-------------->", qual_data["qualification_id"])
                if str(oqual.qualification_id) != str(
                    qual_data["qualification_id"]
                ):  # working deletion now
                    # print(
                    #     str(qual_data["qualification_id"])
                    #     + " != "
                    #     + str(oqual.qualification_id)
                    # )
                    instance.perm_position_master.qualification.remove(oqual)

        for qual_data in validated_data["perm_position_master"][
            "qualification"
        ]:  # working for addition too.
            instance.perm_position_master.qualification.add(
                qual_data["qualification_id"]
            )

        # qualification_job_history
        # print(
        #     "validated_data['perm_position_master']['qualification_job_history']---------->",
        #     validated_data["perm_position_master"]["qualification_job_history"],
        # )
        if not validated_data["perm_position_master"][
            "qualification_job_history"
        ]:  # working for empty role.
            for oexp in oldexp:
                instance.perm_position_master.qualification_job_history.remove(oexp)
                # print("exp deleted")

        for oexp in oldexp:
            for exp_data in validated_data["perm_position_master"][
                "qualification_job_history"
            ]:
                # print(
                #     "qual_data.qualification_job_id-------------->",
                #     exp_data["qualification_job_id"],
                # )
                if str(oexp.qualification_job_id) != str(
                    exp_data["qualification_job_id"]
                ):  # working deletion now
                    # print(
                    #     str(exp_data["qualification_job_id"])
                    #     + " != "
                    #     + str(oexp.qualification_job_id)
                    # )
                    instance.perm_position_master.qualification_job_history.remove(oexp)

        for exp_data in validated_data["perm_position_master"][
            "qualification_job_history"
        ]:  # working for addition too.
            instance.perm_position_master.qualification_job_history.add(
                exp_data["qualification_job_id"]
            )

        # documents_required
        # print(
        #     "validated_data['perm_position_master']['documents_required']---------->",
        #     validated_data["perm_position_master"]["documents_required"],
        # )
        if not validated_data["perm_position_master"][
            "documents_required"
        ]:  # working for empty role.
            for odoc in olddoc:
                instance.perm_position_master.documents_required.remove(odoc)
                # print("doc deleted")

        for odoc in olddoc:
            for doc_data in validated_data["perm_position_master"][
                "documents_required"
            ]:
                # print("doc_data.doc_id-------------->", doc_data["doc_id"])
                if str(odoc.doc_id) != str(doc_data["doc_id"]):  # working deletion now
                    # print(str(doc_data["doc_id"]) + " != " + str(odoc.doc_id))
                    instance.perm_position_master.documents_required.remove(odoc)

        for doc_data in validated_data["perm_position_master"][
            "documents_required"
        ]:  # working for addition too.
            instance.perm_position_master.documents_required.add(doc_data["doc_id"])

        # information_required
        # print(
        #     "validated_data['information_required']---------->",
        #     validated_data["perm_position_master"]["information_required"],
        # )
        if not validated_data["perm_position_master"][
            "information_required"
        ]:  # working for empty role.
            for oinfo in oldinfo:
                instance.perm_position_master.information_required.remove(oinfo)
                # print("info deleted")

        for oinfo in oldinfo:
            for info_data in validated_data["perm_position_master"][
                "information_required"
            ]:
                # print("doc_data.info_id-------------->", info_data["info_id"])
                if str(oinfo.info_id) != str(
                    info_data["info_id"]
                ):  # working deletion now
                    # print(str(info_data["info_id"]) + " != " + str(oinfo.info_id))
                    instance.perm_position_master.information_required.remove(oinfo)

        for info_data in validated_data["perm_position_master"][
            "information_required"
        ]:  # working for addition too.
            instance.perm_position_master.information_required.add(info_data["info_id"])

        instance.save()

        return instance.perm_position_id


class TemporaryPositionMasterSerializer(serializers.ModelSerializer):
    temp_position_master = serializers.SerializerMethodField(
        method_name="get_position", read_only=True
    )

    class Meta:
        model = TemporaryPositionMaster
        fields = (
            "temp_position_id",
            "temp_position_master",
            "allowance",
            "salary",
        )

    def get_position(self, obj):
        serializer = NewPositionMasterSerializer(obj.temp_position_master)
        return serializer.data

    def save(self, validated_data):
        posi = NewPositionMaster.objects.create(
            position_name=validated_data["temp_position_master"]["position_name"]
            if "position_name" in validated_data["temp_position_master"]
            else None,
            position_display_name=validated_data["temp_position_master"][
                "position_display_name"
            ],
            min_age=validated_data["temp_position_master"]["min_age"]
            if "min_age" in validated_data["temp_position_master"]
            else None,
            # validated_data["temp_position_master"]["min_age"],
            max_age=validated_data["temp_position_master"]["max_age"]
            if "max_age" in validated_data["temp_position_master"]
            else None,
            qualification_desc=validated_data["temp_position_master"][
                "qualification_desc"
            ]
            if "qualification_desc" in validated_data["temp_position_master"]
            else None,
        )

        qualification = (
            validated_data["temp_position_master"]["qualification"]
            if "qualification" in validated_data["temp_position_master"]
            else None
        )

        if qualification:
            for qualification_data in qualification:
                qualification = QualificationMaster.objects.get(
                    qualification_id=qualification_data["qualification_id"]
                )
                posi.qualification.add(qualification)
            print(
                "validated_data['qualification_job_history']--------->",
                validated_data["temp_position_master"]["qualification_job_history"],
            )

        qualification_hist = (
            validated_data["temp_position_master"]["qualification_job_history"]
            if "qualification_job_history" in validated_data["temp_position_master"]
            else None
        )

        if qualification_hist:
            for exp in qualification_hist:
                emp_exp = QualificationJobHistoryMaster.objects.get(
                    qualification_job_id=exp["qualification_job_id"]
                )
                posi.qualification_job_history.add(emp_exp)
        information = (
            validated_data["temp_position_master"]["information_required"]
            if "information_required" in validated_data["temp_position_master"]
            else None
        )

        if information:
            for info_data in information:
                info = InformationMaster.objects.get(info_id=info_data["info_id"])
                posi.information_required.add(info)

        document = (
            validated_data["temp_position_master"]["documents_required"]
            if "documents_required" in validated_data["temp_position_master"]
            else None
        )

        if document:
            for doc in document:
                docs = NewDocumentMaster.objects.get(doc_id=doc["doc_id"])
                posi.documents_required.add(docs)

        posi = TemporaryPositionMaster.objects.create(
            temp_position_master=posi,
            salary=validated_data.get("salary"),
            allowance="hra",
        )
        print("Done")

        return posi.temp_position_id

    def update(self, instance, validated_data):
        print("instance ----->", instance)
        print("validated_data ---->", validated_data)
        if instance:
            instance.salary = (
                validated_data["salary"]
                if validated_data["salary"]
                else instance.salary
            )
            # for base table entry
            print(instance.temp_position_master.position_name)
            print(
                "validated_data['temp_position_master']['position_name']------------>",
                validated_data["temp_position_master"]["position_name"],
            )
            instance.temp_position_master.position_name = (
                validated_data["temp_position_master"]["position_name"]
                if validated_data["temp_position_master"]["position_name"]
                else instance.temp_position_master.position_name
            )

            instance.temp_position_master.position_display_name = (
                validated_data["temp_position_master"]["position_display_name"]
                if validated_data["temp_position_master"]["position_display_name"]
                else instance.temp_position_master.position_display_name
            )

            instance.temp_position_master.min_age = (
                validated_data["temp_position_master"]["min_age"]
                if validated_data["temp_position_master"]["min_age"]
                else instance.temp_position_master.min_age
            )

            instance.temp_position_master.max_age = (
                validated_data["temp_position_master"]["max_age"]
                if validated_data["temp_position_master"]["max_age"]
                else instance.temp_position_master.max_age
            )
            instance.temp_position_master.qualification_desc = (
                validated_data["temp_position_master"]["qualification_desc"]
                if validated_data["temp_position_master"]["qualification_desc"]
                else instance.temp_position_master.qualification_desc
            )
            instance.temp_position_master.save()
            instance.save()
        posi = NewPositionMaster.objects.get(
            position_id=validated_data["temp_position_master"]["position_id"]
        )
        oldqual = posi.qualification.filter()
        oldexp = posi.qualification_job_history.filter()
        olddoc = posi.documents_required.filter()
        oldinfo = posi.information_required.filter()
        # print(
        #     "validated_data['temp_position_master']['qualification']---------->",
        #     validated_data["temp_position_master"]["qualification"],
        # )
        if not validated_data["temp_position_master"][
            "qualification"
        ]:  # working for empty role.
            for oqual in oldqual:
                instance.temp_position_master.qualification.remove(oqual)
                # print("qual deleted")

        for oqual in oldqual:
            for qual_data in validated_data["temp_position_master"]["qualification"]:
                # print("qual_data.id-------------->", qual_data["qualification_id"])
                if str(oqual.qualification_id) != str(
                    qual_data["qualification_id"]
                ):  # working deletion now
                    # print(
                    #     str(qual_data["qualification_id"])
                    #     + " != "
                    #     + str(oqual.qualification_id)
                    # )
                    instance.temp_position_master.qualification.remove(oqual)

        for qual_data in validated_data["temp_position_master"][
            "qualification"
        ]:  # working for addition too.
            instance.temp_position_master.qualification.add(
                qual_data["qualification_id"]
            )

        # qualification_job_history
        # print(
        #     "validated_data['temp_position_master']['qualification_job_history']---------->",
        #     validated_data["temp_position_master"]["qualification_job_history"],
        # )
        if not validated_data["temp_position_master"][
            "qualification_job_history"
        ]:  # working for empty role.
            for oexp in oldexp:
                instance.temp_position_master.qualification_job_history.remove(oexp)
                # print("exp deleted")

        for oexp in oldexp:
            for exp_data in validated_data["temp_position_master"][
                "qualification_job_history"
            ]:
                # print(
                #     "qual_data.qualification_job_id-------------->",
                #     exp_data["qualification_job_id"],
                # )
                if str(oexp.qualification_job_id) != str(
                    exp_data["qualification_job_id"]
                ):  # working deletion now
                    # print(
                    #     str(exp_data["qualification_job_id"])
                    #     + " != "
                    #     + str(oexp.qualification_job_id)
                    # )
                    instance.temp_position_master.qualification_job_history.remove(oexp)

        for exp_data in validated_data["temp_position_master"][
            "qualification_job_history"
        ]:  # working for addition too.
            instance.temp_position_master.qualification_job_history.add(
                exp_data["qualification_job_id"]
            )

        # documents_required
        # print(
        #     "validated_data['temp_position_master']['documents_required']---------->",
        #     validated_data["temp_position_master"]["documents_required"],
        # )
        if not validated_data["temp_position_master"][
            "documents_required"
        ]:  # working for empty role.
            for odoc in olddoc:
                instance.temp_position_master.documents_required.remove(odoc)
                # print("doc deleted")

        for odoc in olddoc:
            for doc_data in validated_data["temp_position_master"][
                "documents_required"
            ]:
                # print("doc_data.doc_id-------------->", doc_data["doc_id"])
                if str(odoc.doc_id) != str(doc_data["doc_id"]):  # working deletion now
                    # print(str(doc_data["doc_id"]) + " != " + str(odoc.doc_id))
                    instance.temp_position_master.documents_required.remove(odoc)

        for doc_data in validated_data["temp_position_master"][
            "documents_required"
        ]:  # working for addition too.
            instance.temp_position_master.documents_required.add(doc_data["doc_id"])

        # information_required
        # print(
        #     "validated_data['information_required']---------->",
        #     validated_data["temp_position_master"]["information_required"],
        # )
        if not validated_data["temp_position_master"][
            "information_required"
        ]:  # working for empty role.
            for oinfo in oldinfo:
                instance.temp_position_master.information_required.remove(oinfo)
                # print("info deleted")

        for oinfo in oldinfo:
            for info_data in validated_data["temp_position_master"][
                "information_required"
            ]:
                # print("doc_data.info_id-------------->", info_data["info_id"])
                if str(oinfo.info_id) != str(
                    info_data["info_id"]
                ):  # working deletion now
                    # print(str(info_data["info_id"]) + " != " + str(oinfo.info_id))
                    instance.temp_position_master.information_required.remove(oinfo)

        for info_data in validated_data["temp_position_master"][
            "information_required"
        ]:  # working for addition too.
            instance.temp_position_master.information_required.add(info_data["info_id"])

        instance.save()

        return instance.temp_position_id


# NewPositionMaster


class P_MasterSerializer(serializers.ModelSerializer):
    class Meta:
        model = NewPositionMaster
        fields = ("position_name",)


# class SubjectSpecializationqualificationSerializer(serializers.ModelSerializer):
#     score = serializers.SerializerMethodField(
#         method_name="get_score", read_only=True
#     )
#
#     class Meta:
#         model = UserEducationDetails
#         fields = (
#             "id",
#             "specialization",
#             "score",
#         )
#
#     def get_score(self, obj):
#         score = obj.score + obj.score_unit
#         return score


class NewPositionMasterSerializer(serializers.ModelSerializer):
    documents_required = serializers.SerializerMethodField(
        method_name="get_documents_required", required=False
    )

    information_required = serializers.SerializerMethodField(
        method_name="get_information_required", required=False
    )

    qualification = serializers.SerializerMethodField(
        method_name="get_qualification", required=False
    )
    qualification_job_history = serializers.SerializerMethodField(
        method_name="get_qualification_job_history", required=False
    )

    class Meta:
        model = NewPositionMaster
        fields = (
            "position_id",
            "position_name",
            "position_display_name",
            "min_age",
            "max_age",
            "qualification_desc",
            "documents_required",
            "information_required",
            "qualification",
            "qualification_job_history",
        )

    def get_documents_required(self, obj):
        doc_req = obj.documents_required.filter()
        serializer = NewDocumentMasterSerializer(doc_req, many=True)
        return serializer.data

    def get_information_required(self, obj):
        info_req = obj.information_required.filter()
        serializer = InformationMasterSerializer(info_req, many=True)
        return serializer.data

    def get_qualification(self, obj):
        qual = obj.qualification.filter()
        serializer = QualificationMasterSerializer(qual, many=True)
        return serializer.data

    def get_qualification_job_history(self, obj):
        qual_job = obj.qualification_job_history.filter()
        serializer = QualificationJobHistoryMasterSerializer(qual_job, many=True)
        return serializer.data

    def save(self, validated_data):

        position = NewPositionMaster.objects.create(
            position_name=validated_data["position_name"],
            position_display_name=validated_data["position_display_name"],
            min_age=validated_data["min_age"],
            max_age=validated_data["max_age"],
            qualification_desc=validated_data["qualification_desc"],
        )

        # position = PositionMaster.objects.get(position_id=validated_data['position']['position_id'])
        # template.position = position
        # template.save()
        print("validated_data--------->", validated_data)

        for qualification_data in validated_data["qualification"]:
            qualification = QualificationMaster.objects.get(
                qualification_id=qualification_data["qualification_id"]
            )
            position.qualification.add(qualification)
        print(
            "validated_data['qualification_job_history']--------->",
            validated_data["qualification_job_history"],
        )

        for exp in validated_data["qualification_job_history"]:
            print("exp--------->", exp)
            emp_exp = QualificationJobHistoryMaster.objects.get(
                qualification_job_id=exp["qualification_job_id"]
            )
            position.qualification_job_history.add(emp_exp)

        for info_data in validated_data["information_required"]:
            info = InformationMaster.objects.get(info_id=info_data["info_id"])
            position.information_required.add(info)

        for doc in validated_data["documents_required"]:
            docs = NewDocumentMaster.objects.get(doc_id=doc["doc_id"])
            position.documents_required.add(docs)

        return position.position_id

    def update(self, instance, validated_data):
        print("instance ----->", instance)
        print("instance.position_name ----->", instance.position_name)
        print("validated_data ---->", validated_data)
        instance.position_name = (
            validated_data["position_name"]
            if validated_data["position_name"]
            else instance.position_name
        )

        instance.position_display_name = (
            validated_data["position_display_name"]
            if validated_data["position_display_name"]
            else instance.position_display_name
        )

        instance.min_age = (
            validated_data["min_age"] if validated_data["min_age"] else instance.min_age
        )

        instance.max_age = (
            validated_data["max_age"] if validated_data["max_age"] else instance.max_age
        )
        instance.qualification_desc = (
            validated_data["qualification_desc"]
            if validated_data["qualification_desc"]
            else instance.qualification_desc
        )

        instance.save()
        posi = NewPositionMaster.objects.get(position_id=validated_data["position_id"])
        oldqual = posi.qualification.filter()
        oldexp = posi.qualification_job_history.filter()
        olddoc = posi.documents_required.filter()
        oldinfo = posi.information_required.filter()
        print(
            "validated_data['qualification']---------->",
            validated_data["qualification"],
        )
        if not validated_data["qualification"]:  # working for empty role.
            for oqual in oldqual:
                instance.qualification.remove(oqual)
                print("qual deleted")

        for oqual in oldqual:
            for qual_data in validated_data["qualification"]:
                print("qual_data.id-------------->", qual_data["qualification_id"])
                if str(oqual.qualification_id) != str(
                    qual_data["qualification_id"]
                ):  # working deletion now
                    print(
                        str(qual_data["qualification_id"])
                        + " != "
                        + str(oqual.qualification_id)
                    )
                    instance.qualification.remove(oqual)

        for qual_data in validated_data["qualification"]:  # working for addition too.
            instance.qualification.add(qual_data["qualification_id"])

        # qualification_job_history
        print(
            "validated_data['qualification_job_history']---------->",
            validated_data["qualification_job_history"],
        )
        if not validated_data["qualification_job_history"]:  # working for empty role.
            for oexp in oldexp:
                instance.qualification_job_history.remove(oexp)
                print("exp deleted")

        for oexp in oldexp:
            for exp_data in validated_data["qualification_job_history"]:
                print(
                    "qual_data.qualification_job_id-------------->",
                    exp_data["qualification_job_id"],
                )
                if str(oexp.qualification_job_id) != str(
                    exp_data["qualification_job_id"]
                ):  # working deletion now
                    print(
                        str(exp_data["qualification_job_id"])
                        + " != "
                        + str(oexp.qualification_job_id)
                    )
                    instance.qualification_job_history.remove(oexp)

        for exp_data in validated_data[
            "qualification_job_history"
        ]:  # working for addition too.
            instance.qualification_job_history.add(exp_data["qualification_job_id"])

        # documents_required
        print(
            "validated_data['documents_required']---------->",
            validated_data["documents_required"],
        )
        if not validated_data["documents_required"]:  # working for empty role.
            for odoc in olddoc:
                instance.documents_required.remove(odoc)
                print("doc deleted")

        for odoc in olddoc:
            for doc_data in validated_data["documents_required"]:
                # print("doc_data.doc_id-------------->", doc_data["doc_id"])
                if str(odoc.doc_id) != str(doc_data["doc_id"]):  # working deletion now
                    print(str(doc_data["doc_id"]) + " != " + str(odoc.doc_id))
                    instance.documents_required.remove(odoc)

        for doc_data in validated_data[
            "documents_required"
        ]:  # working for addition too.
            instance.documents_required.add(doc_data["doc_id"])

        # information_required
        print(
            "validated_data['information_required']---------->",
            validated_data["information_required"],
        )
        if not validated_data["information_required"]:  # working for empty role.
            for oinfo in oldinfo:
                instance.information_required.remove(oinfo)
                print("info deleted")

        for oinfo in oldinfo:
            for info_data in validated_data["information_required"]:
                print("doc_data.info_id-------------->", info_data["info_id"])
                if str(oinfo.info_id) != str(
                    info_data["info_id"]
                ):  # working deletion now
                    print(str(info_data["info_id"]) + " != " + str(oinfo.info_id))
                    instance.information_required.remove(oinfo)

        for info_data in validated_data[
            "information_required"
        ]:  # working for addition too.
            instance.information_required.add(info_data["info_id"])

        instance.save()
        return instance.position_id
