from django.db import models
import uuid
from django.db.models import Q, UniqueConstraint
from user.models import BaseModel


class CommunicationType(BaseModel):

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    communication_type = models.CharField(max_length=100,null=True,blank=True)
    is_deleted = models.BooleanField(default=False,help_text="Used for Soft Delete")

    def __str__(self):
        return self.communication_type


class CommunicationActionType(BaseModel):

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    comm_action_type = models.CharField(max_length=100,null=True,blank=True)
    is_deleted = models.BooleanField(default=False,help_text="Used for Soft Delete")

    def __str__(self):
        return self.comm_action_type


class CommunicationMaster(BaseModel):

    communication_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    communication_name = models.CharField(max_length=100,null=True,blank=True)
    subject = models.CharField(max_length=200,null=True,blank=True)
    body = models.TextField(blank=True, null=True)
    comm_type = models.ForeignKey('CommunicationType',null=True, blank=True, on_delete=models.SET_NULL,
                                   related_name="comm_type")
    action_type = models.ForeignKey('CommunicationActionType',null=True, blank=True, on_delete=models.SET_NULL,
                                   related_name="communication_action_type")
    is_active = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False, help_text="Used for Soft Delete")

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["comm_type", "action_type", "is_active"], condition=Q(is_active=True), name='unique_level_per_comm_type'),
        ]

    def __str__(self):
        return ' '.join([self.communication_name, self.comm_type.communication_type, self.action_type.comm_action_type])