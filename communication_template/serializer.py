from rest_framework import serializers
from django.db import transaction
from communication_template.models import CommunicationMaster, CommunicationType, CommunicationActionType


class CommunicationTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = CommunicationType
        fields = (
            "id",
            "communication_type",
        )


class CommunicationActionTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = CommunicationActionType
        fields = (
            "id",
            "comm_action_type",
        )


class CommunicationMasterSerializer(serializers.ModelSerializer):
    comm_type = CommunicationTypeSerializer(required=False)
    action_type = CommunicationActionTypeSerializer(required=False)

    class Meta:
        model = CommunicationMaster

        fields = (
            "communication_id",
            "communication_name",
            "subject",
            "body",
            "is_active",
            "is_deleted",
            "comm_type",
            "action_type",
        )

    def save(self, validated_data):
        with transaction.atomic():
            type_data = validated_data['comm_type']
            action_type_data = validated_data['action_type']
            comm_type = CommunicationType.objects.get(communication_type__exact=type_data['communication_type'])
            action_type = CommunicationActionType.objects.get(
                comm_action_type__exact=action_type_data['comm_action_type'])
            if validated_data['is_active'] and CommunicationMaster.objects.filter(
                    action_type__comm_action_type__icontains=action_type,
                    comm_type__communication_type__icontains=comm_type,
                    is_active=True).exists():
                commu = CommunicationMaster.objects.get(action_type__comm_action_type__icontains=action_type,
                                                        comm_type__communication_type__icontains=comm_type,
                                                        is_active=True)
                commu.is_active = False
                commu.save()
            communication = CommunicationMaster.objects.create(
                communication_name=validated_data['communication_name'],
                subject=validated_data['subject'],
                body=validated_data['body'],
                is_active=validated_data['is_active'],
            )
            communication.comm_type = comm_type
            communication.action_type = action_type
            communication.save()
            return communication.communication_id

    def update(self, instance, validated_data):
        com_type = validated_data['comm_type']['communication_type']
        act_type = validated_data['action_type']['comm_action_type']
        if validated_data['is_active'] and CommunicationMaster.objects.filter(
                action_type__comm_action_type__icontains=act_type, comm_type__communication_type__icontains=com_type,
                is_active=True).exists():
            commu = CommunicationMaster.objects.get(action_type__comm_action_type__icontains=act_type,
                                                    comm_type__communication_type__icontains=com_type,
                                                    is_active=True)
            commu.is_active = False
            commu.save()
        if instance:
            instance.communication_name = (
                validated_data['communication_name'] if validated_data[
                    'communication_name'] else instance.communication_name
            )
            instance.subject = (
                validated_data['subject'] if validated_data['subject'] else instance.subject
            )
            instance.body = (
                validated_data['body'] if validated_data['body'] else instance.body
            )
            instance.is_active = validated_data['is_active']
            instance.is_deleted = (
                validated_data['is_deleted'] if validated_data['is_deleted'] else instance.is_deleted
            )
            instance.save()
            return instance.communication_id