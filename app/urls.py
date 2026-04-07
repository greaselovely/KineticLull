from django.urls import path
from django.urls import re_path
from django.conf import settings
from django.views.static import serve
from django.conf.urls.static import static
from django.contrib.auth.views import LoginView
from django.views.generic.base import RedirectView

from . import views
from .views import SubmitFQDNView, update_edl_fqdn, short_urls_view, create_short_url, edit_short_url, delete_short_url, redirect_short_url, restart_services_view

app_name = "app"

urlpatterns = [
    path('', views.favorites_view, name='home'),
    path('edls/', views.index_view, name='index'),
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
    path('upgrade/', views.upgrade_view, name='upgrade'),
    path('deployment/', views.deployment_status_view, name='deployment_status'),
    path('deployment/migrate/', views.deployment_migrate_view, name='deployment_migrate'),
    path('blocked-ips/', views.blocked_ips_view, name='blocked_ips'),
    path('api/block-ip/', views.block_ip_view, name='block_ip'),
    path('api/unblock-ip/', views.unblock_ip_view, name='unblock_ip'),
    path('api/blocked-ip-timeline/', views.blocked_ip_timeline_view, name='blocked_ip_timeline'),
    path('api/whitelist-ip/', views.whitelist_ip_view, name='whitelist_ip'),
    path('api/remove-whitelist-ip/', views.remove_whitelist_ip_view, name='remove_whitelist_ip'),
    path('api/restart-services/', restart_services_view, name='restart_services'),
    path('blocked-ips/export/', views.blocklist_export_view, name='blocklist_export'),
    path('favorites/', views.favorites_view, name='favorites'),  # legacy redirect support
    path('favorite/<int:item_id>/', views.toggle_favorite, name='toggle_favorite'),
    path('logs/', views.activity_log_view, name='activity_log'),
    path('logs/export/', views.activity_log_export, name='activity_log_export'),
    path('settings/', views.app_settings_view, name='app_settings'),
    path('settings/restore/', views.restore_data_view, name='restore_data'),
    path('integrity/', views.integrity_check_view, name='integrity_check'),
    path('users/', views.user_list_view, name='user_list'),
    path('users/create/', views.user_create_view, name='user_create'),
    path('users/<int:user_id>/edit/', views.user_edit_view, name='user_edit'),
    path('users/<int:user_id>/delete/', views.user_delete_view, name='user_delete'),
    path('groups/', views.group_list_view, name='group_list'),
    path('groups/create/', views.group_create_view, name='group_create'),
    path('groups/<int:group_id>/edit/', views.group_edit_view, name='group_edit'),
    path('urls/', short_urls_view, name='short_urls'),
    path('urls/create/', create_short_url, name='create_short_url'),
    path('urls/<int:url_id>/edit/', edit_short_url, name='edit_short_url'),
    path('urls/delete/<int:url_id>/', delete_short_url, name='delete_short_url'),
    path('files/', views.otf_list_view, name='otf_list'),
    path('files/upload/', views.otf_upload_view, name='otf_upload'),
    path('f/<str:token>/', views.otf_download_view, name='otf_download'),
    path('s/<str:short_code>/', redirect_short_url, name='redirect_short_url'),
    path('favicon.ico', RedirectView.as_view(url='/static/images/favicon.ico', permanent=True)),
    # keep this at the bottom
    re_path(r'^(?P<auto_url>[\w.-]+)/?$', views.show_ip_fqdn, name='show_ip_fqdn'),
]
