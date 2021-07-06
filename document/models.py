from django.db import models
import uuid
from user.models import BaseModel


CASTE = "caste"
PERSONAL = "personal"
QUALIFICATION = "qualification"
EXPERIENCE = "experience"
PUBLISHED_PAPERS = "published papers"
OTHERS = "others"


DOC_TYPE_CHOICES = [
    (CASTE, "CASTE"),
    (PERSONAL, "PERSONAL"),
    (QUALIFICATION, "QUALIFICATION"),
    (EXPERIENCE, "EXPERIENCE"),
    (PUBLISHED_PAPERS, "PUBLISHED_PAPERS"),
    (OTHERS, "OTHERS"),
]


class NewDocumentMaster(BaseModel):
    doc_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    doc_name = models.CharField(max_length=50, null=True, blank=True)
    doc_type = models.CharField(
        max_length=30, choices=DOC_TYPE_CHOICES, null=True, blank=True
    )

    def __str__(self):
        return self.doc_type


# Required Information Enum:
# "Personal"
# "Reservation"
# "Education: Graduation"
# "Education: Post Graduation"
# "Education: Doctorate"
# "Skills: Typing Speed"
# "Publication: Published Papers"
# "References"
# "Job History"
# "International Trips"
# "Relatives in NEERI"


RESERVATION = "reservation"
PERSONAL = "personal"
GRADUATION = "graduation"
POST_GRADUATION = "post graduation"
DOCTORATE = "education doctorate"
TYPING_SPEED = "typing speed"
PUBLISHED_PAPERS = "published papers"
REFERENCES = "references"
JOB_HISTORY = "job history"
INTERNATIONAL_TRIPS = "international trips"
RELATIVES_IN_NEERI = "relatives in neeri"

INFO_TYPE_CHOICES = [
    (RESERVATION, "RESERVATION"),
    (PERSONAL, "PERSONAL"),
    (GRADUATION, "GRADUATION"),
    (POST_GRADUATION, "POST_GRADUATION"),
    (DOCTORATE, "DOCTORATE"),
    (TYPING_SPEED, "TYPING_SPEED"),
    (PUBLISHED_PAPERS, "PUBLISHED_PAPERS"),
    (REFERENCES, "REFERENCES"),
    (JOB_HISTORY, "JOB_HISTORY"),
    (INTERNATIONAL_TRIPS, "INTERNATIONAL_TRIPS"),
    (RELATIVES_IN_NEERI, "RELATIVES_IN_NEERI"),
]


class InformationMaster(BaseModel):
    info_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    info_name = models.CharField(max_length=50, null=True, blank=True)
    info_type = models.CharField(
        max_length=30, choices=INFO_TYPE_CHOICES, null=True, blank=True
    )

    def __str__(self):
        return self.info_type
