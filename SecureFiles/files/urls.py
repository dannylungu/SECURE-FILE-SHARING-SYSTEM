from django.urls import path
from . import views

urlpatterns = [
    path('upload/', views.file_upload_view, name='file_upload'),
    path('', views.file_list_view, name='file_list'),
    path('download/<int:file_id>/', views.file_download_view, name='file_download'),
    path('share/<int:file_id>/', views.file_share_view, name='file_share'),
    path('view/<int:file_id>/', views.file_view_view, name='file_view'),
    path('delete/<int:file_id>/', views.file_delete_view, name='file_delete'),
    path('remove-shared/<int:file_id>/', views.remove_shared_file_view, name='remove_shared_file'),
]