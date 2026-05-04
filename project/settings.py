import os
import random
import string
from pathlib import Path
from urllib.parse import urlparse
from dotenv import load_dotenv

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def generate_random_string(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    temp_key = ''.join(random.choice(characters) for i in range(length))
    temp_key = temp_key.replace("'", "KL") # cleanup so string.punctuation doesn't fowl up the stored string with a single-quote.
    return temp_key

dotenv_path = os.path.join(os.path.dirname(__file__), '.env')

if not os.path.isfile(dotenv_path):
    # clear()
    kl_url_question = input("[?]\tWhat is the IP or FQDN this will be accessible at?\n[i]\tInclude https:// with it (ie...https://10.1.1.1 / https://edl.kineticlull.com) : ")
    print("[i]\tTo update this, edit the project/.env file\n\n")
    secret_key = generate_random_string(65)
    debug = 'False'

    with open(dotenv_path, 'w') as f:
        f.write(f'KINETICLULL_URL = \'{kl_url_question}\'\n')
        f.write(f'SECRET_KEY = \'{secret_key}\'\n')
        f.write(f'DEBUG = \'{debug}\'\n')
    load_dotenv(dotenv_path)
else:
    load_dotenv(dotenv_path)

LOGIN_URL = 'app:login'
LOGIN_REDIRECT_URL = '/'

BASE_DIR = Path(__file__).resolve().parent.parent

KINETICLULL_URL = os.getenv('KINETICLULL_URL')
SECRET_KEY = os.getenv('SECRET_KEY')
DEBUG = os.getenv('DEBUG') == 'True'

# DEBUG = True


_kl_host = urlparse(KINETICLULL_URL).hostname if KINETICLULL_URL else None
ALLOWED_HOSTS = [_kl_host, 'localhost', '127.0.0.1'] if _kl_host else ['localhost', '127.0.0.1']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sessions',
    'users',
    'app',
    # 'debug_toolbar',
]

MIDDLEWARE = [
    # 'debug_toolbar.middleware.DebugToolbarMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'app.middleware.TimezoneCheckMiddleware',
]

ROOT_URLCONF = 'project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'app/static/templates/'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'app.context_processors.inbox_count',
                'app.context_processors.app_settings',
                'app.context_processors.health_summary',
            ],
        },
    },
]

WSGI_APPLICATION = 'project.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

SESSION_SAVE_EVERY_REQUEST = True
SESSION_COOKIE_AGE = 1800  # 30 min default, overridden by AppSettings at runtime

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STORAGES = {
    'default': {
        'BACKEND': 'django.core.files.storage.FileSystemStorage',
    },
    'staticfiles': {
        'BACKEND': 'whitenoise.storage.CompressedManifestStaticFilesStorage',
    },
}

MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')
DATA_UPLOAD_MAX_MEMORY_SIZE = 262144000  # 250MB
FILE_UPLOAD_MAX_MEMORY_SIZE = 262144000  # 250MB

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

AUTH_USER_MODEL = 'users.CustomUser'

INTERNAL_IPS = ['127.0.0.1',]

# Proxy headers (safe unconditionally; only apply when headers are present)
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
USE_X_FORWARDED_HOST = True
USE_X_FORWARDED_PORT = True

# Logging #
KINETICLULL_LOG_FILE = "kineticlull.log"
LOG_DIR = BASE_DIR / 'logs'
LOG_DIR.mkdir(exist_ok=True)
LOG_PATH = Path.joinpath(LOG_DIR, KINETICLULL_LOG_FILE)
if not LOG_PATH: 
    LOG_PATH.touch()

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{asctime} {levelname} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': LOG_PATH,
            'maxBytes': 1024*1024*5,  # 5 MB
            'backupCount': 5,  # keep 5 old copies
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': True,
        },
        'app': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}
