"""Bake DB-level defaults into the columns added in 0039.

Without db_default, Django's `default=''` only applies at the ORM layer.
Old workers (pre-0039 code) build INSERTs that omit the new columns, and
SQLite then rejects with NOT NULL violation because the column has no
DB-side default. Adding db_default='' makes the schema itself supply ''.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0039_activitylog_ua_referer_shortenedurl_title'),
    ]

    operations = [
        migrations.AlterField(
            model_name='activitylog',
            name='user_agent',
            field=models.CharField(blank=True, db_default='', default='', max_length=512),
        ),
        migrations.AlterField(
            model_name='activitylog',
            name='referer',
            field=models.CharField(blank=True, db_default='', default='', max_length=512),
        ),
        migrations.AlterField(
            model_name='shortenedurl',
            name='title',
            field=models.CharField(blank=True, db_default='', default='', max_length=255, verbose_name='Title'),
        ),
    ]
