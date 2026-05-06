from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0038_appsettings_autoblock_subnet_aggregation_enabled_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='activitylog',
            name='user_agent',
            field=models.CharField(blank=True, default='', max_length=512),
        ),
        migrations.AddField(
            model_name='activitylog',
            name='referer',
            field=models.CharField(blank=True, default='', max_length=512),
        ),
        migrations.AddField(
            model_name='shortenedurl',
            name='title',
            field=models.CharField(blank=True, default='', max_length=255, verbose_name='Title'),
        ),
    ]
