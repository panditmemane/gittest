from rest_framework.generics import ListAPIView
from rest_framework.views import APIView
from django.http import JsonResponse
from rest_framework import status
from rest_framework.response import Response
from document.models import NewDocumentMaster, InformationMaster
from document.serializer import NewDocumentMasterSerializer, InformationMasterSerializer
from rest_framework.filters import OrderingFilter, SearchFilter


class DocumentSearchListView(ListAPIView):
    queryset = NewDocumentMaster.objects.all()
    serializer_class = NewDocumentMasterSerializer
    filter_backends = [SearchFilter]
    search_fields = ('doc_id', 'doc_name', 'doc_type')


class InformationSearchListView(ListAPIView):
    queryset = InformationMaster.objects.all()
    serializer_class = InformationMasterSerializer
    filter_backends = [SearchFilter]
    search_fields = ('info_id', 'info_name', 'info_type')

# New Docs serializer
class NewDocumentListView(APIView):

    def get(self, request, *args, **kwargs):
        try:
            id = self.kwargs['id']
            if NewDocumentMaster.objects.filter(doc_id=id, is_deleted=False).exists():
                doc = NewDocumentMaster.objects.get(doc_id=id, is_deleted=False)
                serializer = NewDocumentMasterSerializer(doc)
                return Response(serializer.data, status=200)
            else:
                return Response(data={"message": "Details Not Found."}, status=401)
        except:
            docs = NewDocumentMaster.objects.filter(is_deleted=False).order_by('doc_name')
            serializer = NewDocumentMasterSerializer(docs, many=True)
            return Response(serializer.data, status=200)

    def delete(self,request,*args,**kwargs):
        try:
            id = self.kwargs['id']
            doc = NewDocumentMaster.objects.get(doc_id=id)
            doc.is_deleted = True
            doc.save()
            return Response(data = {"messege":"Document Deleted Successfully(Soft Delete)."}, status=200)
        except:
            return Response(data={"messege": "Document Not Found."}, status=401)

    def put(self, request, *args, **kwargs):
        id = self.kwargs['id']
        doc = NewDocumentMaster.objects.get(doc_id=id)
        data = self.request.data
        serializer = NewDocumentMasterSerializer(doc, data=data)
        serializer.is_valid(raise_exception=True)
        serializer.update(instance=doc, validated_data=data)
        return Response(serializer.data, status=200)

    def post(self, request, *args, **kwargs):
        data = self.request.data
        serializer = NewDocumentMasterSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=200)


class InformationListView(APIView):

    def get(self, request, *args, **kwargs):
        try:
            id = self.kwargs['id']
            if InformationMaster.objects.filter(info_id=id, is_deleted=False).exists():
                info = InformationMaster.objects.get(info_id=id, is_deleted=False)
                serializer = InformationMasterSerializer(info)
                return Response(serializer.data, status=200)
            else:
                return Response(data={"message": "Details Not Found."}, status=401)
        except:
            info = InformationMaster.objects.filter(is_deleted=False).order_by('info_name')
            serializer = InformationMasterSerializer(info, many=True)
            return Response(serializer.data, status=200)

    def delete(self,request,*args,**kwargs):
        try:
            id = self.kwargs['id']
            info = InformationMaster.objects.get(info_id=id)
            info.is_deleted = True
            info.save()
            return Response(data = {"message": "info Deleted Successfully(Soft Delete)."}, status=200)
        except:
            return Response(data={"message": "info Not Found."}, status=401)

    def put(self, request, *args, **kwargs):
        id = self.kwargs['id']
        info = InformationMaster.objects.get(info_id=id)
        data = self.request.data
        serializer = InformationMasterSerializer(info, data=data)
        serializer.is_valid(raise_exception=True)
        serializer.update(instance=info, validated_data=data)
        return Response(serializer.data, status=200)

    def post(self, request, *args, **kwargs):
        data = self.request.data
        serializer = InformationMasterSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=200)

