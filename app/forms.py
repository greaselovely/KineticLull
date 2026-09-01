from django import forms
# from .models import ExtDynLists, Script
from .models import ExtDynLists, ShortenedURL
from django.contrib.auth.forms import UserChangeForm
from users.models import CustomUser


class ExtDynListsForm(forms.ModelForm):

    # The system EDL's name, entries and notes are maintained by KineticLull.
    # They are dropped from the form entirely rather than rendered read-only and
    # re-submitted: they are required fields, and an install with an empty
    # blocklist has an empty ip_fqdn, which would fail validation and silently
    # refuse to save the one thing that *is* editable here, the ACL.
    SYSTEM_MANAGED_FIELDS = ('friendly_name', 'ip_fqdn', 'policy_reference')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if getattr(self.instance, 'is_system', False):
            for name in self.SYSTEM_MANAGED_FIELDS:
                self.fields.pop(name, None)


    class Meta:
        model = ExtDynLists
        # The ACL relations are rendered as checkbox lists in the template and
        # set explicitly in the views, so they stay out of the auto-built form.
        # Note this Meta uses `exclude`, so anything added to the model and not
        # listed here would otherwise appear in the form unannounced.
        exclude = ('auto_url', 'groups', 'acl_firewalls', 'acl_firewall_groups',)
        widgets = {
            'friendly_name' : forms.TextInput(attrs={'class' : 'form-control mb-3', 
                                              'id' : 'friendlyNameInput', 
                                              'placeholder' : 'KL EDL Name', 
                                              'required' : 'required'}),
            'ip_fqdn' : forms.Textarea(attrs={'class' : 'form-control mb-3',
                                              'id' : 'ipFqdnInput', 
                                              'placeholder' : 'Example:\n127.0.0.1 Comments Can Be Used\nexample.com Another Comment\ndomain.com Text After The First Space Is Ignored By The Firewall', 
                                              'required' : 'required',
                                              'rows' : '4'}),
            'acl' : forms.Textarea(attrs={'class' : 'form-control mb-3',
                                              'id' : 'aclInput', 
                                              'placeholder' : 'Optional. Leave blank to allow only the firewalls selected alongside.\n*\n1.1.1.1\n10.0.0.0/24\n2001:db8::1\n# A note, or a commented-out entry', 
                                              'rows' : '5'}),
            'policy_reference' : forms.Textarea(attrs={'class' : 'form-control mb-3',
                                              'id' : 'policyReferenceInput', 
                                              'placeholder' : 'Security Policy Reference\nTicket Number\nOther Notes', 
                                              'required' : 'required',
                                              'rows' : '4'}),
        }


class ShortenedURLForm(forms.ModelForm):
    class Meta:
        model = ShortenedURL
        fields = ['title', 'original_url', 'notes']
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-control form-control-sm mb-3',
                'id': 'titleInput',
                'placeholder': 'Friendly name for this link',
                'required': 'required',
            }),
            'original_url': forms.TextInput(attrs={
                'class': 'form-control form-control-sm mb-3',
                'id': 'originalUrlInput',
                'placeholder': 'https://example.com/long/url - or mailto:you@example.com',
                'required': 'required',
            }),
            'notes': forms.Textarea(attrs={
                'class': 'form-control form-control-sm mb-3',
                'id': 'notesInput',
                'placeholder': 'Reference notes (e.g., used in email signature, shared with team)',
                'rows': '3',
            }),
        }


# class ScriptForm(forms.ModelForm):
#     class Meta:
#         model = Script
#         fields = ['name', 'content', 'is_approved']
#         widgets = {
#             'name': forms.TextInput(attrs={'class': 'form-control mb-3'}),
#             'content': forms.Textarea(attrs={'class': 'form-control mb-3'}),
#             'is_approved': forms.CheckboxInput(attrs={'class': 'form-check-input mb-3'}),
#         }
