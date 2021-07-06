from django.contrib import admin
from django.urls import path
from communication_template.views import RetrievetCommunicationTemplateView, DeleteCommunicationTemplateView, \
    UpdateCommunicationTemplateView, CreateCommunicationTemplateView, CommunicationTemplateListView, \
    CommunicationTypeListView, CommunicationActionTypeListView, CommunicationTemplateSearchListView, \
    CommunicationTemplateFilterListView

urlpatterns = [
    path('get_template/<uuid:id>/', RetrievetCommunicationTemplateView.as_view(), name="get-template"),
    path('delete_template/<uuid:id>/', DeleteCommunicationTemplateView.as_view(), name="delete-template"),
    path('update_template/<uuid:id>/', UpdateCommunicationTemplateView.as_view(), name="update-template"),
    path('create_template/', CreateCommunicationTemplateView.as_view(), name="create-template"),
    path('template_list/', CommunicationTemplateListView.as_view(), name="template-list"),
    path('search_template/', CommunicationTemplateSearchListView.as_view(), name="search-template-list"),
    path('filter_template/', CommunicationTemplateFilterListView.as_view(), name="filter-template-list"),
    path('template_type_list/', CommunicationTypeListView.as_view(), name="template-type-list"),
    path('template_action_type_list/', CommunicationActionTypeListView.as_view(), name="template-action-type-list"),
]
