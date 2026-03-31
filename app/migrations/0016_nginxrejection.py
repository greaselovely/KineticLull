from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0015_blockedip_and_autoblock_settings'),
    ]

    operations = [
        migrations.CreateModel(
            name='NginxRejection',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.GenericIPAddressField(db_index=True)),
                ('path', models.CharField(max_length=500)),
                ('timestamp', models.DateTimeField(db_index=True)),
            ],
            options={
                'verbose_name': 'Nginx Rejection',
                'verbose_name_plural': 'Nginx Rejections',
                'ordering': ['-timestamp'],
                'indexes': [
                    models.Index(fields=['ip_address', 'timestamp'], name='app_nginxrej_ip_addr_ts_idx'),
                ],
            },
        ),
    ]
