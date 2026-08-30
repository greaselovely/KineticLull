from django.contrib import admin
from django.urls import path, include
from django.conf import settings

from app.api import api as api_v1

handler404 = 'app.views.custom_404'

urlpatterns = [
    # path('admin/', admin.site.urls),  # Disabled - use in-app user management instead
    # Mounted ahead of the app include: app/urls.py ends in a catch-all that
    # serves EDLs by slug, and it must never see an API path.
    path('api/v1/', api_v1.urls),
    path('', include('app.urls')),
]

# if settings.DEBUG:
#     import debug_toolbar
#     urlpatterns = [
#         path('__debug__/', include(debug_toolbar.urls)),
#     ] + urlpatterns