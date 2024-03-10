from django.contrib import admin
# from .models import ExtDynLists, InboxEntry, Script
from .models import ExtDynLists, InboxEntry

admin.site.register(ExtDynLists)
admin.site.register(InboxEntry)
# admin.site.register(Script)