from django.contrib import admin
from django.urls import path, include
from django.conf import settings

handler404 = 'app.views.custom_404'

urlpatterns = [
    # path('admin/', admin.site.urls),  # Disabled — use in-app user management instead
    path('', include('app.urls')),
]

# if settings.DEBUG:
#     import debug_toolbar
#     urlpatterns = [
#         path('__debug__/', include(debug_toolbar.urls)),
#     ] + urlpatterns