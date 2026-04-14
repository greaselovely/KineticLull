from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0027_appsettings_resend_from_name'),
    ]

    operations = [
        migrations.AddField(
            model_name='appsettings',
            name='failed_login_block_enabled',
            field=models.BooleanField(default=True, verbose_name='Enable Failed-Login Block'),
        ),
        migrations.AddField(
            model_name='appsettings',
            name='failed_login_block_threshold',
            field=models.PositiveIntegerField(default=3, verbose_name='Failed-Login Block Threshold'),
        ),
        migrations.AddField(
            model_name='appsettings',
            name='failed_login_warning_threshold',
            field=models.PositiveIntegerField(default=2, verbose_name='Failed-Login Warning Threshold'),
        ),
        migrations.AddField(
            model_name='appsettings',
            name='failed_login_window_hours',
            field=models.PositiveIntegerField(default=24, verbose_name='Failed-Login Window (hours)'),
        ),
    ]
