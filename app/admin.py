from django.contrib import admin
from .models import ExtDynLists, InboxEntry, Favorite, ActivityLog, AppSettings, ShortenedURL, WhitelistedIP, OneTimeFile

admin.site.register(ExtDynLists)
admin.site.register(InboxEntry)
admin.site.register(Favorite)
admin.site.register(ActivityLog)
admin.site.register(AppSettings)
admin.site.register(ShortenedURL)
admin.site.register(WhitelistedIP)
admin.site.register(OneTimeFile)
