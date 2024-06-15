from django.urls import path
from django.urls import re_path
from django.conf import settings
from django.views.static import serve
from django.conf.urls.static import static
from django.contrib.auth.views import LoginView

from . import views
from .views import SubmitFQDNView, update_edl_fqdn

app_name = "app"

urlpatterns = [
    path('', views.index_view, name='index'),
    path('edit/', views.edit_ext_dyn_list_view, name="edit"),
    path('edit/<id>', views.edit_ext_dyn_list_view, name="edit"),
    path('clone/', views.clone_ext_dyn_list_view, name="clone"),
    path('clone/<int:item_id>/', views.clone_ext_dyn_list_view, name="clone"),
    path('add/', views.create_new_edl, name="new_edl"),
    path('delete/<int:item_id>/', views.delete_item, name='delete_item'),
    path('download_ip_fqdn/<int:item_id>/', views.download_ip_fqdn, name='download_ip_fqdn'),
    path('login/', LoginView.as_view(template_name='login.html'), name='login'),
    path('accounts/profile/', views.profile_view, name='profile'),
    path('edit-profile/', views.edit_profile_view, name='edit_profile'),
    path('logout/', views.logout_view, name='logout'),
    path('item-detail/<int:item_id>/', views.item_detail_view, name='item_detail'),
    path('api/submit_fqdn/', SubmitFQDNView.as_view(), name='submit_fqdn'),
    path('api/update_edl/', update_edl_fqdn, name='update_edl'),
    path('submission_list/', views.submission_list, name='submission_list'),
    # path('script_list/', views.script_list, name='script_list'),
    path('review_submission/<int:submission_id>/', views.review_submission, name='review_submission'),
    path('delete_submission/<int:submission_id>/', views.delete_submission, name='delete_submission'),
    # path('review_script/<int:script_id>', views.review_script, name='review_script'),
    # keep this at the bottom
    re_path(r'^(?P<auto_url>[\w.-]+)/?$', views.show_ip_fqdn, name='show_ip_fqdn'),
]
