from django.contrib import admin
from .models import ExtDynLists, InboxEntry, Favorite, ActivityLog, AppSettings

admin.site.register(ExtDynLists)
admin.site.register(InboxEntry)
admin.site.register(Favorite)
admin.site.register(ActivityLog)
admin.site.register(AppSettings)
