from django import forms
# from .models import ExtDynLists, Script
from .models import ExtDynLists, ShortenedURL
from django.contrib.auth.forms import UserChangeForm
from users.models import CustomUser


class ExtDynListsForm(forms.ModelForm):

    class Meta:
        model = ExtDynLists
        exclude = ('auto_url', 'groups',)
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
                                              'placeholder' : 'Example:\n* (Any)\n1.1.1.1\n10.0.0.0/24\n#A Note Can Be Entered or Line Commented Out Like This', 
                                              'required' : 'required',
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
        fields = ['original_url', 'notes']
        widgets = {
            'original_url': forms.URLInput(attrs={
                'class': 'form-control mb-3',
                'id': 'originalUrlInput',
                'placeholder': 'https://example.com/very/long/url/to/shorten',
                'required': 'required',
            }),
            'notes': forms.Textarea(attrs={
                'class': 'form-control mb-3',
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
