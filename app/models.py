from django.db import models
from django.conf import settings

class ExtDynLists(models.Model):
    friendly_name = models.CharField(max_length=255, verbose_name='EDL Name')
    auto_url = models.CharField(max_length=255)
    ip_fqdn = models.TextField(verbose_name='IP/FQDN')
    acl = models.TextField(verbose_name='ACL')
    policy_reference = models.TextField(verbose_name='Notes')
    # use_script = models.ForeignKey('Script', on_delete=models.CASCADE, verbose_name='Script', null=True, blank=True)
    created_date = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Ext Dyn List"
        verbose_name_plural = "Ext Dyn Lists"
        ordering = ["created_date", "friendly_name"]

    def __str__(self):
        return f"{self.id}: {self.friendly_name} ({self.auto_url})" 

    # def update(self):
    #     if self.use_script and self.use_script.is_approved:
    #         # Execute the script as it has been approved
    #         exec(self.use_script.content)  # Be cautious with `exec`, as it poses a security risk
    #     else:
    #         print(f"Script for {self.friendly_name} is not approved or found.")


class InboxEntry(models.Model):
    user_email = models.CharField(max_length=255, verbose_name='E-Mail Address')
    fqdn_list = models.TextField(verbose_name='IP/FQDN')
    submitted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "API Submission"
        verbose_name_plural = "API Submissions"

# class Script(models.Model):
#     name = models.CharField(max_length=255, verbose_name='Script Name')
#     content = models.TextField(verbose_name='Script Content')
#     creator = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='created_scripts', verbose_name='Script Creator', null=True)
#     is_approved = models.BooleanField(default=False, verbose_name='Approved for Execution')

#     class Meta:
#         verbose_name = "Script"
#         verbose_name_plural = "Scripts"

#     def __str__(self):
#         return self.name