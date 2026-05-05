# Generated for system blocklist EDL feature

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0034_appsettings_backup_time'),
    ]

    operations = [
        migrations.AddField(
            model_name='extdynlists',
            name='is_system',
            field=models.BooleanField(default=False, editable=False),
        ),
        migrations.AlterModelOptions(
            name='extdynlists',
            options={
                'ordering': ['-is_system', 'created_date', 'friendly_name'],
                'verbose_name': 'Ext Dyn List',
                'verbose_name_plural': 'Ext Dyn Lists',
            },
        ),
        migrations.AddConstraint(
            model_name='extdynlists',
            constraint=models.UniqueConstraint(
                condition=models.Q(('is_system', True)),
                fields=('is_system',),
                name='unique_system_edl',
            ),
        ),
    ]
