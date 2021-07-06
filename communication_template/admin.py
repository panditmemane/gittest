from django.contrib import admin
from django.contrib.admin import register
from communication_template.models import CommunicationActionType, CommunicationType, CommunicationMaster

@register(CommunicationType)
class TemplateTypeAdmin(admin.ModelAdmin):
    list_display = ['id','communication_type','is_deleted']

@register(CommunicationActionType)
class TemplateTypeAdmin(admin.ModelAdmin):
    list_display = ['id','comm_action_type','is_deleted']

@register(CommunicationMaster)
class CommunicationMasterAdmin(admin.ModelAdmin):
    list_display = ['communication_id','communication_name','subject','body','comm_type', 'action_type', 'is_active','is_deleted']