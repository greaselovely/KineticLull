from django.views import View
from django.urls import reverse
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import logout
from django.core.paginator import Paginator
from django.http import HttpResponseRedirect
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
def item_detail_view(request, item_id: int):
    """
    Retrieves and displays details for a specific External Dynamic List (EDL) item identified by its item_id.
    
    This view fetches an EDL instance from the database using the provided item_id. If the item exists, its 'ip_fqdn'
    field, which is a string containing network addresses separated by carriage returns and new lines, is split into a
    list for easier display. The item details, including its friendly name, are then passed to the template for rendering.

    Parameters:
    - request: HttpRequest object representing the current request.
    - item_id: The ID of the EDL item whose details are to be displayed.

    Returns:
    - HttpResponse object with the rendered page displaying the details of the specified EDL item.
    """
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
    """
    Handles the creation of a new External Dynamic List (EDL) entry through a form. If the request is POST and the form is valid,
    a new EDL instance is created, populated with the form data, and saved to the database with additional processing for the 'acl'
    field. If the request is GET, an empty form is presented to the user.

    Upon a successful POST request, the 'acl' field is processed to filter out blank lines and correct each network address
    before saving. The function redirects to the home page after successful EDL creation or re-renders the form with errors
    on validation failure.

    Parameters:
    - request: HttpRequest object representing the current request.

    Returns:
    - HttpResponse object with the rendered form for creating a new EDL on GET requests, or a redirect to the home page
      after successfully creating an EDL on POST requests. In case of form validation failure, re-renders the form with errors.
    """
    if request.method == 'POST':
        form = ExtDynListsForm(request.POST)
        if form.is_valid():
            edl_instance = form.save(commit=False)
            edl_instance.auto_url = generate_hash()

            # Process each line in acl, filtering out only blank lines
            acl_lines = (line.strip() for line in edl_instance.acl.splitlines())
            corrected_acl = [get_corrected_network_address(line) for line in acl_lines if line]
            
            edl_instance.ip_fqdn = "\r\n".join([fqdn.replace("http://", "").replace("https://", "") for fqdn in edl_instance.ip_fqdn.split('\r\n')])
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
                edl_instance.ip_fqdn = "\r\n".join([fqdn.replace("http://", "").replace("https://", "") for fqdn in edl_instance.ip_fqdn.split('\r\n')])
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
    Delete a specific item from the database based on its ID and redirects back to the original page.

    This function retrieves an item using its unique ID from the ExtDynLists model.
    If the item exists, it is deleted. Otherwise, a 404 error is raised. After
    deletion, the function attempts to redirect back to the original page using the
    'HTTP_REFERER' header from the request. If this header is not available, it redirects
    to a fallback URL (e.g., the home page).

    Parameters:
    - request: HttpRequest object representing the current request.
    - item_id (int): The unique identifier of the item to be deleted.

    Returns:
    - HttpResponseRedirect: Redirects to the referring page or to a fallback URL after the item is deleted.
    """
    item = get_object_or_404(ExtDynLists, id=item_id)
    item.delete()

    # Attempt to redirect back to the original page using 'HTTP_REFERER'
    referer_url = request.META.get('HTTP_REFERER')
    if referer_url:
        return HttpResponseRedirect(referer_url)
    else:
        # Fallback URL if 'HTTP_REFERER' is not available
        return redirect(reverse('app:index'))  # Adjust 'app:submission_list' to your named URL for the list view

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
    """
    Allows the user to edit their profile, including generating a new API key
    and updating user information through a form. If the request method is POST
    and contains 'generate_api_key', the existing API key for the user is deleted,
    and a new one is generated. If the form is submitted and valid, the user's profile
    is updated. Otherwise, the edit profile form is displayed.

    Args:
        request: HttpRequest object.

    Returns:
        HttpResponse object rendering the edit profile page with the context
        containing the form, title, and API key if present.
    """
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
    """
    Renders the profile page for the logged-in user.

    This view displays the user's profile information, including their API key if it exists. It's a straightforward
    view that primarily deals with presenting information to the user without handling any form submissions or
    data modifications.

    Parameters:
    - request: HttpRequest object containing metadata about the request.

    Returns:
    - HttpResponse object with the rendered profile page.
    """
    context = {"title": "Profile"}
    return render(request, 'profile.html', context)

def generate_api_key(user):
    """
    Generates a new API key for a given user. If an API key already exists for the user, it updates the existing key.

    This function uses `secrets.token_urlsafe()` to generate a secure, random API key. It ensures that each user has only
    one API key by checking for an existing key and updating it if found. If no key exists, it creates a new APIKey instance.

    Parameters:
    - user: User instance for whom the API key is being generated or updated.

    Returns:
    - A tuple containing the new API key string and a boolean indicating whether the API key was created (True) or updated (False).
    """
    api_key, created = APIKey.objects.get_or_create(user=user)
    new_key = secrets.token_urlsafe(50)  # Generates a secure URL-safe text string
    api_key.key = new_key
    api_key.save()
    return new_key, created

def validate_api_key(key: str) -> bool:
    """
    Validates an API key by checking if it exists in the database.

    This function queries the database to see if the provided API key exists within the APIKey model. It's used
    to verify that an API key is valid and has been issued, as part of authentication or permission checks in
    API or system operations that require key-based access control.

    Parameters:
    - key: A string representing the API key to be validated.

    Returns:
    - A boolean value: True if the API key exists in the database, False otherwise.
    """
    return APIKey.objects.filter(key=key).exists()

def authenticate_user(api_key_header):
    """
    Authenticates a user based on an API key provided in the header.

    This function expects the `api_key_header` to be in the format "Bearer YOUR_API_KEY_HERE". It attempts to
    extract the API key from the header and then checks if this key corresponds to an existing APIKey instance
    in the database. If a matching APIKey instance is found, the associated user is returned, otherwise, None
    is returned, indicating that authentication has failed.

    Parameters:
    - api_key_header: The API key header string, expected to start with "Bearer " followed by the API key.

    Returns:
    - The user associated with the provided API key if authentication is successful; otherwise, None.
    """
    try:
        _, api_key = api_key_header.split()  # This unpacks the header into two parts: "Bearer" and the actual key
    except ValueError:
        # If split() fails or doesn't produce exactly two items, then we have only received the key already and just assign it for user lookup.
        api_key = api_key_header

    try:
        api_key_instance = APIKey.objects.get(key=api_key)
        return api_key_instance.user
    except APIKey.DoesNotExist:
        return None

def logout_view(request):
    """
    Logs out the user and redirects them to the homepage.

    This view handles the process of logging out a user by deleting the sessionid and csrftoken cookies,
    effectively invalidating the user's session. It then calls Django's logout function to officially
    log the user out before redirecting the user to the homepage.

    Parameters:
    - request: HttpRequest object representing the current request.

    Returns:
    - An HttpResponseRedirect to the homepage, with session and CSRF cookies removed.
    """
    response = redirect('/')
    response.delete_cookie('sessionid')
    response.delete_cookie('csrftoken')
    logout(request)
    return response

@csrf_exempt
@require_http_methods(["POST"])
def submit_fqdn_list(request):
    """
    Receives a list of FQDNs (Fully Qualified Domain Names) via a POST request, cleanses it by removing
    any protocol prefixes (http://, https://), and stores it in the database associated with the authenticated user.

    This view is CSRF exempt and only accepts POST requests. It expects the request to contain a JSON body
    with a key 'fqdn_list' that maps to a list of FQDN strings. The function authenticates the user based on
    an API key provided in the 'Authorization' header, validates the FQDN list, and then creates a new InboxEntry
    with the cleansed FQDN list.

    Parameters:
    - request: HttpRequest object representing the current request.

    Returns:
    - JsonResponse indicating success or failure. On success, returns HTTP 201 with a message
      'Submission successful'. On failure, returns HTTP 400/401/500 with an error message.
    """
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
        fqdn_list = [domain.replace("http://", "").replace("https://", "") for domain in fqdn_list]

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
    """
    A class-based view that handles the submission of FQDN (Fully Qualified Domain Names) lists via a POST request.
    It authenticates the user using an API key provided in the 'Authorization' header, validates the FQDN list,
    and then stores it in the database associated with the user's email.

    The view is CSRF exempt to facilitate API access. It ensures that the FQDN list is not empty, does not exceed
    50 entries, and sanitizes the list by removing any protocol prefixes before storing.

    Methods:
    - post: Handles POST requests, expecting a JSON body with a 'fqdn_list' key mapping to a list of FQDN strings.
    
    Returns:
    - JsonResponse indicating success with HTTP 201 status code, or an error with appropriate HTTP status codes
      (401 for invalid API key, 400 for invalid FQDN list, etc.) and error messages.
    """
    def post(self, request, *args, **kwargs):
        api_key = request.headers.get('Authorization')
        user = authenticate_user(api_key)
        
        if user is None:
            return JsonResponse({'error': 'Invalid API key'}, status=401)
        
        data = json.loads(request.body)
        fqdn_list = data.get('fqdn_list', [])
        fqdn_list = [domain.replace("http://", "").replace("https://", "") for domain in fqdn_list]
        
        if not fqdn_list or len(fqdn_list) > 50:
            return JsonResponse({'error': f'Invalid FQDN list {data} {type(data)}'}, status=400)
        
        InboxEntry.objects.create(user_email=user.email, fqdn_list="\r\n".join(fqdn_list))

        return JsonResponse({'message': 'Submission successful'}, status=201)

@csrf_exempt
@require_http_methods(["POST"])
def update_edl_fqdn(request):
    """
    Updates an External Dynamic List (EDL) with new Fully Qualified Domain Names (FQDNs) based on the provided command.
    It supports adding new FQDNs or overwriting the existing list with a new set of FQDNs. The function performs
    user authentication using an API key, validates the request data, and applies the specified changes to the EDL.

    The request must include 'auto_url' to identify the EDL, 'fqdn_list' containing the domains to add or overwrite,
    and 'command' indicating the update operation mode ('update' or 'overwrite'). FQDNs are cleansed of protocols
    (http://, https://) before processing.

    Parameters:
    - request: HttpRequest object containing metadata about the request including 'Authorization' header with the API key,
               and a JSON body with 'auto_url', 'fqdn_list', and 'command'.

    Returns:
    - JsonResponse indicating the outcome of the operation. Returns HTTP 201 with a success message if the update
      is successful, HTTP 401 for unauthorized requests, HTTP 400 for requests with missing or invalid data,
      or HTTP 500 for server errors.
    """
    try:
        current_date_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        data = json.loads(request.body)
        auth_header = request.headers.get('Authorization')
        api_key = auth_header.split(' ')[-1] if auth_header else None
        user = authenticate_user(api_key)
        user = str(user)
        user, _ = user.split("@")

        if user is None:
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        # Extract the auto_url from the request data
        full_auto_url = data.get('auto_url', '')
        fqdn_list = data.get('fqdn_list', [])
        fqdn_list = [domain.replace("http://", "").replace("https://", "") for domain in fqdn_list]
        command = data.get('command', 'update')  # Default to 'update'

        # Obtain the base URL from settings or .env
        base_url = getattr(settings, 'KINETICLULL_URL', os.getenv('KINETICLULL_URL', ''))

        # Remove the base URL part from the full_auto_url
        if base_url and full_auto_url.startswith(base_url):
            auto_url = full_auto_url.replace(base_url, '', 1).lstrip('/')
        else:
            auto_url = full_auto_url

        if not auto_url:
            return JsonResponse({'error': 'Missing auto_url'}, status=400)

        if not fqdn_list or len(fqdn_list) > 50:
            return JsonResponse({'error': 'Empty or Too Long FQDN list'}, status=400)

        try:
            edl = ExtDynLists.objects.get(auto_url=auto_url)
        except ExtDynLists.DoesNotExist:
            return JsonResponse({'error': 'EDL not found'}, status=404)

        if command == 'overwrite':
            # For 'overwrite', treat all provided domains as new
            edl.ip_fqdn = "\r\n".join([f"{domain} # {current_date_time} by {user}" for domain in set(fqdn_list)])
        elif command == 'update':
            existing_fqdns = edl.ip_fqdn.split("\r\n")
            
            # Extract just the domain names from existing entries to identify new domains
            existing_domains = set(entry.split(' ')[0] for entry in existing_fqdns if ' ' in entry)  # Assumes space-delimited
            
            # Determine which domains from the provided list are new
            new_domains = [domain for domain in fqdn_list if domain not in existing_domains]
            
            # Append additional info only to new domains
            new_fqdn_entries = [f"{domain} # {current_date_time} by {user}" for domain in new_domains]
            
            # Combine new entries with existing ones, no need to deduplicate here as existing entries are preserved as is
            updated_fqdns = existing_fqdns + new_fqdn_entries
            edl.ip_fqdn = "\r\n".join(updated_fqdns)
        
        else:
            return JsonResponse({'error': 'Invalid Command'}, status=400)

        edl.save()
        return JsonResponse({'message': 'Command Successful'}, status=200)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'error': 'An error occurred', 'details': str(e)}, status=500)

@login_required
def review_submission(request, submission_id: int):
    """
    Presents a form for reviewing and processing a submission entry. Upon a POST request, if the form is valid,
    a new External Dynamic List (EDL) is created using the data from the submission, and the submission is then deleted.

    The function handles both GET and POST requests. For GET requests, it pre-populates a form with information
    from the submission, including a policy reference constructed from the submission's timestamp and user email.
    For POST requests, it processes the form data, creates a new EDL entry, deletes the processed submission,
    and redirects to the submission list view.

    Parameters:
    - request: HttpRequest object representing the current request.
    - submission_id: The ID of the submission entry to review and process.

    Returns:
    - HttpResponse object with the rendered review page on GET requests or a redirect on successful form processing.
    """
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
def delete_submission(request, submission_id: int):
    """
    Deletes a specified submission entry and redirects to the submission list view.

    This view retrieves an InboxEntry object by its `submission_id` and deletes it from the database.
    After deletion, the user is redirected to the list of submissions, typically to update the UI and
    show the list without the deleted entry.

    Parameters:
    - request: HttpRequest object representing the current request.
    - submission_id: The ID of the submission entry to be deleted.

    Returns:
    - An HttpResponseRedirect to the submission list view after the deletion.
    """
    submission = get_object_or_404(InboxEntry, id=submission_id)
    submission.delete()
    return redirect('app:submission_list')

@login_required
def submission_list(request):
    """
    Retrieves and displays a list of all submission entries.

    This view fetches all instances of InboxEntry from the database, splits the 'fqdn_list' field of each
    submission into a list of FQDNs (for display purposes), and passes the submissions to the template for rendering.
    It's designed to provide an overview of all submissions, allowing users to review, edit, or delete them as needed.

    Parameters:
    - request: HttpRequest object representing the current request.

    Returns:
    - HttpResponse object with the rendered page displaying the list of submissions.
    """
    submissions = InboxEntry.objects.all()
    for submission in submissions:
        submission.fqdn_list = submission.fqdn_list.split('\r\n')
    return render(request, 'submission_list.html', {'submissions' : submissions},)

# @login_required
# def script_list(request):
#     script_list = Script.objects.all()
#     # print(script_list.name)
#     return render(request, 'script_list.html', {'script_list' : script_list},)

# @login_required
# def review_script(request, script_id):
#     script = get_object_or_404(Script, id=script_id)
#     is_creator = request.user == script.creator
    
#     if request.method == "POST":
#         form = ScriptForm(request.POST, instance=script)
#         if form.is_valid():
#             form.save()
#             return redirect('app:script_list')
#     else:
#         form = ScriptForm(instance=script)
#         if is_creator:
#             # Exclude the 'is_approved' field for the creator of the script
#             # Can't self-approve your own scripts
#             form.fields.pop('is_approved')

#     context = {
#         'form': form
#         }
#     return render(request, 'review_script.html', context)

# @login_required
# def approve_script(request, script_id):
#     script = get_object_or_404(Script, id=script_id)
#     if request.user != script.creator and request.user.has_perm('app.can_approve_script'):
#         script.is_approved = True
#         script.save()
#         # Redirect to the review page or display success message
#         return redirect('script_review')
#     else:
#         raise PermissionDenied