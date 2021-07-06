from django.contrib import admin
from django.urls import path
from document.views import NewDocumentListView, InformationListView, DocumentSearchListView, InformationSearchListView

urlpatterns = [

    # new docs
    path('docs/', NewDocumentListView.as_view(), name="docs-list"),
    path('search_docs/', DocumentSearchListView.as_view(), name="search-docs-list"),
    path('docs/<uuid:id>/', NewDocumentListView.as_view(), name="docs"),

    # new docs
    path('info/', InformationListView.as_view(), name="docs-list"),
    path('search_info/', InformationSearchListView.as_view(), name="docs-list"),
    path('info/<uuid:id>/', InformationListView.as_view(), name="docs"),

]
