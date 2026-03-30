from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0013_fix_zero_defaults'),
    ]

    operations = [
        migrations.AddField(
            model_name='appsettings',
            name='deployment_mode',
            field=models.CharField(
                choices=[('gunicorn_ssl', 'Gunicorn (direct SSL)'), ('nginx_gunicorn', 'Nginx + Gunicorn')],
                default='gunicorn_ssl',
                max_length=20,
                verbose_name='Deployment Mode',
            ),
        ),
    ]
