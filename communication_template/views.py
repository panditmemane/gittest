from rest_framework.generics import ListAPIView
from rest_framework.views import APIView
from rest_framework.response import Response
from communication_template.models import CommunicationMaster, CommunicationType, CommunicationActionType
from communication_template.serializer import CommunicationMasterSerializer, CommunicationTypeSerializer, \
    CommunicationActionTypeSerializer
from rest_framework.filters import SearchFilter

class CommunicationTypeListView(APIView):
    def get(self, request, *args, **kwargs):
        docs = CommunicationType.objects.filter(is_deleted=False)
        serializer = CommunicationTypeSerializer(docs, many=True)
        return Response(serializer.data, status=200)


class CommunicationActionTypeListView(APIView):
    def get(self, request, *args, **kwargs):
        docs = CommunicationActionType.objects.filter(is_deleted=False)
        serializer = CommunicationActionTypeSerializer(docs, many=True)
        return Response(serializer.data, status=200)



class CommunicationTemplateSearchListView(ListAPIView):
    queryset = CommunicationMaster.objects.all()
    serializer_class = CommunicationMasterSerializer
    filter_backends = [SearchFilter]
    search_fields = ('subject', 'body')


class CommunicationTemplateFilterListView(ListAPIView):
        queryset = CommunicationMaster.objects.all()
        serializer_class = CommunicationMasterSerializer
        filterset_fields = ['communication_name', 'subject', 'comm_type__communication_type', 'action_type__comm_action_type', 'is_active']

class CommunicationTemplateListView(APIView):
    def get(self, request, *args, **kwargs):
        docs = CommunicationMaster.objects.filter(is_deleted=False).order_by('communication_name')
        serializer = CommunicationMasterSerializer(docs, many=True)
        return Response(serializer.data, status=200)


class CreateCommunicationTemplateView(APIView):
    def post(self, request, *args, **kwargs):
        data = self.request.data
        data_serializer = CommunicationMasterSerializer(data=data)
        data_serializer.is_valid(raise_exception=True)
        try:
            result_data = data_serializer.save(validated_data=data)
            result_serializer = CommunicationMasterSerializer(result_data)
            return Response(result_serializer.data, status=200)
        except:
            return Response(data={"message": "Constraint Violated"}, status=400)

class RetrievetCommunicationTemplateView(APIView):
    def get(self, request, *args, **kwargs):
        id = self.kwargs['id']
        template = CommunicationMaster.objects.get(communication_id=id, is_deleted=False)
        serializer = CommunicationMasterSerializer(template)
        return Response(serializer.data, status=200)

class UpdateCommunicationTemplateView(APIView):
    def put(self, request, *args, **kwargs):
        id = self.kwargs['id']
        template = CommunicationMaster.objects.get(communication_id=id)
        data = self.request.data
        serializer = CommunicationMasterSerializer(template, data=data)
        serializer.is_valid(raise_exception=True)
        try:
            serializer.update(instance=template, validated_data=data)
            return Response(serializer.data, status=200)
        except:
            return Response(data = {"messege":"Constraint Violated"}, status=401)


class DeleteCommunicationTemplateView(APIView):
    def delete(self, request, *args, **kwargs):
        try:
            id = self.kwargs['id']
            template = CommunicationMaster.objects.get(communication_id=id)
            template.is_deleted = True
            template.save()
            return Response(data={"message": "Record Deleted Successfully(Soft Delete)."}, status=200)
        except:
            return Response(data={"message": "Details Not Found."}, status=401)

