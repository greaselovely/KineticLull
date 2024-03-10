from django.views import View
from django.urls import reverse
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import logout
from django.core.paginator import Paginator
from django.utils.crypto import get_random_string
from django.http import HttpResponse, JsonResponse
from django.core.exceptions import PermissionDenied
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.shortcuts import render, redirect, get_object_or_404

import os
import json
import secrets
import hashlib
import ipaddress
from datetime import datetime

from users.models import APIKey
# from .models import InboxEntry, ExtDynLists, Script
from .models import InboxEntry, ExtDynLists
# from .forms import ExtDynListsForm, CustomUserChangeForm, ScriptForm
from .forms import ExtDynListsForm, CustomUserChangeForm


@login_required
def index_view(request):
    """
    Display the index view with a list of ExtDynLists items.

    This view retrieves all ExtDynLists items and prepares them for display. For each item, 
    it constructs the full URL by appending the 'auto_url' to the base URL. The base URL is 
    obtained from Django settings or environment variables. Additionally, it processes the 
    'ip_fqdn' field to display a limited number of entries with an ellipsis if the count 
    exceeds a certain threshold (e.g., more than 3 entries). The 'ip_fqdn_count' and a flag 
    'display_ellipsis' are set for each item accordingly.

    Parameters:
    request: The HttpRequest object.

    Returns:
    HttpResponse: Renders the 'index.html' template with the context containing the list of 
                ExtDynLists items and their processed data.
    """

    items = ExtDynLists.objects.all()
    paginator = Paginator(items, 5)
    base_url = settings.KINETICLULL_URL if hasattr(settings, 'KINETICLULL_URL') else os.environ.get('KINETICLULL_URL', 'http://127.0.0.1:8000')
    # print(base_url)
    for item in items:
        item.full_url = base_url + ('/' if item.auto_url[0] != '/' else '') + item.auto_url
        item.ip_fqdn = item.ip_fqdn.split('\r\n')
        item.ip_fqdn_count = len(item.ip_fqdn)
        item.display_ellipsis = item.ip_fqdn_count >= 4
        item.ip_fqdn = item.ip_fqdn[:3]
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    context = {'items': items, 'page_obj': page_obj}
    return render(request, 'index.html', context)

@login_required
def item_detail_view(request, item_id):
    item = get_object_or_404(ExtDynLists, id=item_id)
    item.ip_fqdn = item.ip_fqdn.split('\r\n')
    context = {'item': item, 'friendly_name': item.friendly_name }
    return render(request, 'item_detail.html', context)


def generate_hash():
    """
    Generate a unique hash string based on the current datetime.

    This function generates a hash using the SHA-256 algorithm, applied to the current 
    datetime string. The generated hash is truncated to the last 10 characters and 
    appended with '.kl' to create a unique identifier.

    Returns:
    str: A unique hash string derived from the current datetime, truncated to the 
        last 10 characters and appended with '.kl'.
    """

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hash_object = hashlib.sha256(current_time.encode())
    hash_object = hash_object.hexdigest()[-10:] + ".kl"
    return hash_object

def show_ip_fqdn(request, auto_url):
    """
    Display the IP/FQDN for a given ExtDynLists item based on its auto URL.

    This view retrieves an ExtDynLists item using the provided auto URL. If the item is found,
    it checks if the user's IP address is allowed access based on the ACL list of the item.
    If the IP address is allowed (either explicitly or via a wildcard '*'), the 'ip_fqdn' field 
    of the item is returned as a plain text response. If the IP address is not allowed, a 
    PermissionDenied exception is raised.

    Parameters:
    request: The HttpRequest object.
    auto_url (str): The auto-generated URL identifier for the ExtDynLists item.

    Returns:
    HttpResponse: A HttpResponse object with 'text/plain' content type, containing the
                'ip_fqdn' data if access is allowed.
    Raises:
    PermissionDenied: If the user's IP address is not allowed access as per the ACL list.
    """

    edl = get_object_or_404(ExtDynLists, auto_url=auto_url)
    acl_list = edl.acl.split('\n')
    user_ip = request.META.get('REMOTE_ADDR')
    if '*' in acl_list or check_acl(user_ip, acl_list):
        return HttpResponse(edl.ip_fqdn, content_type="text/plain")
    else:
        raise PermissionDenied

@login_required
def create_new_edl(request):
    if request.method == 'POST':
        form = ExtDynListsForm(request.POST)
        if form.is_valid():
            edl_instance = form.save(commit=False)
            edl_instance.auto_url = generate_hash()

            # Process each line in acl, filtering out only blank lines
            acl_lines = (line.strip() for line in edl_instance.acl.splitlines())
            corrected_acl = [get_corrected_network_address(line) for line in acl_lines if line]

            edl_instance.acl = "\n".join(corrected_acl)
            edl_instance.save()
            return redirect('/')
        else:
            print(form.errors)
    else:
        form = ExtDynListsForm(initial={'acl': '*', })

    return render(request, 'edit_edl.html', {'form': form})

@login_required
def edit_ext_dyn_list_view(request, id=None):
    """
    Edit an existing ExtDynLists item.

    This view handles the editing of an ExtDynLists item. It first tries to retrieve the item 
    using the provided ID. If the item is found and the request is a POST, the form is 
    processed. Valid form submissions apply corrections to the 'acl' field, such as formatting 
    network addresses and removing blank lines. The corrected 'acl' is then saved. If the 
    form is invalid, or if the request is not a POST, the form is displayed for editing, 
    pre-populated with the item's current data. If no ID is provided, the function allows 
    creating a new item.

    Parameters:
    request: The HttpRequest object.
    id (int, optional): The unique identifier of the item to be edited. If None, a new item 
                        creation form is displayed.

    Returns:
    HttpResponse: Redirects to the home page on successful edit or creation. Otherwise, 
                renders the 'edit_edl.html' template with the form.
    """
    if id:
        edl = get_object_or_404(ExtDynLists, id=id)
        if request.method == 'POST':
            form = ExtDynListsForm(request.POST, instance=edl)
            if form.is_valid():
                # Apply corrections to the acl field
                edl_instance = form.save(commit=False)

                # Process each line in acl, filtering out only blank lines
                acl_lines = (line.strip() for line in edl_instance.acl.splitlines())
                corrected_acl = [get_corrected_network_address(line) for line in acl_lines if line]

                edl_instance.acl = "\n".join(corrected_acl)
                edl_instance.save()
                return redirect("/", pk=id)
        else:
            form = ExtDynListsForm(instance=edl)
    else:
        if request.method == 'POST':
            form = ExtDynListsForm(request.POST)
            if form.is_valid():
                form.save()
                return redirect("/")
        else:
            form = ExtDynListsForm()

    template_name = "edit_edl.html"
    context = {"form": form}
    return render(request, template_name=template_name, context=context)

@login_required
def clone_ext_dyn_list_view(request, item_id):
    """
    Create a clone of an existing ExtDynLists item.

    This view handles the cloning of an ExtDynLists item. It first retrieves the original item 
    using its ID. If the item is found and a POST request is made with valid form data, 
    a new ExtDynLists item is created with data from the form, except for the ID and auto_url, 
    which are set to None and a new hash, respectively. The cloned item is then saved to the 
    database. If the request is not POST or the form data is invalid, the form is displayed 
    initially populated with data from the original item, with '-Copy' appended to the 
    'friendly_name'.

    Parameters:
    request: The HttpRequest object.
    item_id (int): The unique identifier of the item to be cloned.

    Returns:
    HttpResponse: If POST and form is valid, redirects to the home page. Otherwise, renders 
                the 'edit_edl.html' template with the form.
    """

    original_item = get_object_or_404(ExtDynLists, id=item_id)
    
    if request.method == 'POST':
        form = ExtDynListsForm(request.POST)
        if form.is_valid():
            cloned_item = ExtDynLists(**form.cleaned_data)
            cloned_item.id = None
            cloned_item.friendly_name
            cloned_item.auto_url = generate_hash()
            cloned_item.save()
            return redirect('/')
        else:
            print(form.errors)
    else:
        date_time_format = "%m/%d/%Y @ %H:%M:%S UTC"
        now = datetime.now().strftime(date_time_format)
        initial_data = {
            'friendly_name': original_item.friendly_name + " Clone",
            'ip_fqdn' : original_item.ip_fqdn,
            'acl' : original_item.acl,
            'policy_reference' : f'Cloned from "{original_item.friendly_name}" on {now}:\n{original_item.policy_reference}',
        }
        form = ExtDynListsForm(initial=initial_data)
    
    return render(request, 'edit_edl.html', {'form': form})

@login_required
def download_ip_fqdn(request, item_id):
    """
    Generate and return a text file download of the IP/FQDN data for a specific item.

    This function retrieves an item from the ExtDynLists model using its ID. If the item
    is found, it prepares a response with the 'ip_fqdn' field of the item as a text file
    download. If the item is not found, a 404 error is raised. The response sets the
    'Content-Disposition' header to prompt a file download with a filename based on the
    item's friendly name.

    Parameters:
    request: The HttpRequest object.
    item_id (int): The unique identifier of the item whose IP/FQDN data is to be downloaded.

    Returns:
    HttpResponse: A HttpResponse object with 'text/plain' content type, containing the
                'ip_fqdn' data and set up to prompt a file download.
    """

    item = get_object_or_404(ExtDynLists, id=item_id)
    text_content = item.ip_fqdn
    response = HttpResponse(text_content, content_type='text/plain')
    response['Content-Disposition'] = f'attachment; filename="{item.friendly_name}.txt"'
    return response

@login_required
def delete_item(request, item_id):
    """
    Delete a specific item from the database based on its ID.

    This function retrieves an item using its unique ID from the ExtDynLists model. 
    If the item exists, it is deleted. Otherwise, a 404 error is raised. After 
    deletion, the function redirects to the home page.

    Parameters:
    item_id (int): The unique identifier of the item to be deleted.

    Returns:
    HttpResponseRedirect: Redirects to the home page after the item is deleted.
    """
    item = get_object_or_404(ExtDynLists, id=item_id)
    item.delete()
    return redirect('/')


def check_acl(ip, networks: list):
    """
    Check if a given IP address is part of any of the specified networks.

    This function iterates through a list of network strings and determines 
    whether the given IP address is part of these networks. The function 
    supports both CIDR notations and single IP addresses. Single IP addresses 
    are treated as individual networks (with a /32 subnet mask). Commented 
    lines (starting with '#') in the network list are ignored.

    Parameters:
    ip (str): The IP address to check.
    networks (list of str): A list of network strings in CIDR notation or 
                            single IP addresses. Commented lines are allowed.

    Returns:
    bool: True if the IP address is within any of the specified networks, 
        False otherwise.
    """
    ip_addr = ipaddress.ip_address(ip)
    for network_str in networks:
        if network_str.startswith('#') or network_str.startswith('*'):
            continue  # Ignore comment lines

        # Add '/32' to single IP addresses to treat them as individual networks
        if '/' not in network_str:
            network_str += '/32'

        network = ipaddress.ip_network(network_str, strict=False)
        if ip_addr in network:
            return True
    return False


def get_corrected_network_address(value):
    """
    Corrects the given network address string to a valid format or marks it as an invalid entry.

    This function takes a network address string and attempts to validate it. If the input 
    is a valid single IP address or a valid CIDR notation, it returns the value as-is. 
    If the input is an invalid network address, it converts the string into a comment 
    indicating that it's an invalid entry. The function also handles and preserves existing 
    comments (lines starting with '#') and empty strings without modification.

    Parameters:
    value (str): The network address string to be validated and corrected.

    Returns:
    str: The original valid network address or single IP, a commented string indicating an 
         invalid entry, or the original comment/empty string.
    """
    original_value = value.strip()  # Remove leading/trailing whitespace
    if not original_value or original_value.startswith('#') or original_value == '*':  # Skip empty strings and existing comments
        return original_value  # Return as-is if it's already a comment or empty
    try:
        # Check if it's a single IP or a network
        if '/' in original_value:
            network = ipaddress.ip_network(original_value, strict=False)
            return str(network)
        else:
            ipaddress.ip_address(original_value)
            return original_value
    except ValueError:
        # Invalid IP address or network, turn it into a comment with an explanation
        return f"# Invalid entry: {original_value}"

@login_required
def edit_profile_view(request):
    user = request.user
    if request.method == 'POST':
        if 'generate_api_key' in request.POST:
            APIKey.objects.filter(user=user).delete()
            generate_api_key(user)
            messages.success(request, "New API key generated.")
            return redirect('app:edit_profile')

        form = CustomUserChangeForm(request.POST, instance=user)
        if form.is_valid():
            form.save()
            messages.success(request, "Profile updated successfully.")
            return redirect('app:profile')
    else:
        form = CustomUserChangeForm(instance=user)
        api_key = APIKey.objects.filter(user=user).first()

    context = {
        'form': form,
        'title': 'Edit Profile',
        'api_key': api_key.key if api_key else None
    }
    return render(request, 'edit_profile.html', context)



@login_required
def profile_view(request):
    context = {"title": "Profile"}
    return render(request, 'profile.html', context)

# @login_required
def generate_api_key(user):
    api_key, created = APIKey.objects.get_or_create(user=user)
    new_key = get_random_string(50)  # Or use secrets.token_urlsafe()
    api_key.key = new_key
    api_key.save()
    return new_key, created


def validate_api_key(key):
    return APIKey.objects.filter(key=key).exists()

def authenticate_user(api_key_header):
    # Expecting api_key_header to be "Bearer YOUR_API_KEY_HERE"
    # Split the header on whitespace and attempt to get the token part
    try:
        _, api_key = api_key_header.split()  # This unpacks the header into two parts: "Bearer" and the actual key
    except ValueError:
        # If split() fails or doesn't produce exactly two items, return None
        return None

    try:
        api_key_instance = APIKey.objects.get(key=api_key)
        return api_key_instance.user
    except APIKey.DoesNotExist:
        return None



def logout_view(request):
    response = redirect('/')
    response.delete_cookie('sessionid')
    response.delete_cookie('csrftoken')
    logout(request)
    return response


@csrf_exempt
@require_http_methods(["POST"])
def submit_fqdn_list(request):
    # print(request)
    try:
        data = json.loads(request.body)
        auth_header = request.headers.get('Authorization')
        # Strip "Bearer" part if it's there
        api_key = auth_header.split(' ')[-1] if auth_header else None
        user = authenticate_user(api_key)

        if user is None:
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        fqdn_list = data.get('fqdn_list', [])
        if not fqdn_list or len(fqdn_list) > 50:
            return JsonResponse({'error': 'Invalid FQDN list'}, status=400)

        InboxEntry.objects.create(
            user_name=user.username,
            fqdn_list="\n".join(fqdn_list)
        )
        return JsonResponse({'message': 'Submission successful'}, status=201)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        # Catch-all for any other error, ensuring an HttpResponse is always returned
        return JsonResponse({'error': 'An error occurred', 'details': str(e)}, status=500)



@method_decorator(csrf_exempt, name='dispatch')
class SubmitFQDNView(View):
    def post(self, request, *args, **kwargs):
        api_key = request.headers.get('Authorization')
        user = authenticate_user(api_key)
        
        if user is None:
            return JsonResponse({'error': 'Invalid API key'}, status=401)
        
        data = json.loads(request.body)
        fqdn_list = data.get('fqdn_list', [])
        
        if not fqdn_list or len(fqdn_list) > 50:
            return JsonResponse({'error': f'Invalid FQDN list {data} {type(data)}'}, status=400)
        
        InboxEntry.objects.create(user_email=user.email, fqdn_list="\r\n".join(fqdn_list))

        return JsonResponse({'message': 'Submission successful'}, status=201)


@login_required
def review_submission(request, submission_id):
    date_time_format = "%m/%d/%Y @ %H:%M:%S UTC"
    submission = get_object_or_404(InboxEntry, id=submission_id)

    if request.method == 'POST':
        form = ExtDynListsForm(request.POST)
        if form.is_valid():
            new_edl = form.save(commit=False)
            new_edl.auto_url = generate_hash()
            new_edl.fqdn_list = submission.fqdn_list
            new_edl.save()
            submission.delete()
            return redirect('app:submission_list')
    else:
        submitted_at_str = submission.submitted_at.strftime(date_time_format) if submission.submitted_at else "N/A"
        user_email = submission.user_email
        summary_policy_reference = f"Submitted via API on {submitted_at_str} by {user_email}"
        form = ExtDynListsForm(initial={
            'ip_fqdn': submission.fqdn_list,
            'acl' : '*',
            'policy_reference': summary_policy_reference,
        })
    
    return render(request, 'review_submission.html', {
        'form': form,
        'submission': submission,
    })

@login_required
def delete_submission(request, submission_id):
    submission = get_object_or_404(InboxEntry, id=submission_id)
    submission.delete()
    return redirect('app:submission_list')

@login_required
def submission_list(request):
    submissions = InboxEntry.objects.all()
    for submission in submissions:
        submission.fqdn_list = submission.fqdn_list.split('\r\n')
    return render(request, 'submission_list.html', {'submissions' : submissions},)

@login_required
def script_list(request):
    script_list = Script.objects.all()
    # print(script_list.name)
    return render(request, 'script_list.html', {'script_list' : script_list},)

@login_required
def review_script(request, script_id):
    script = get_object_or_404(Script, id=script_id)
    is_creator = request.user == script.creator
    
    if request.method == "POST":
        form = ScriptForm(request.POST, instance=script)
        if form.is_valid():
            form.save()
            return redirect('app:script_list')
    else:
        form = ScriptForm(instance=script)
        if is_creator:
            # Exclude the 'is_approved' field for the creator of the script
            # Can't self-approve your own scripts
            form.fields.pop('is_approved')

    context = {
        'form': form
        }
    return render(request, 'review_script.html', context)

@login_required
def approve_script(request, script_id):
    script = get_object_or_404(Script, id=script_id)
    if request.user != script.creator and request.user.has_perm('app.can_approve_script'):
        script.is_approved = True
        script.save()
        # Redirect to the review page or display success message
        return redirect('script_review')
    else:
        raise PermissionDenied