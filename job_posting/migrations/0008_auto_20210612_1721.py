# Generated by Django 3.1.7 on 2021-06-12 17:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('job_posting', '0007_auto_20210612_1255'),
    ]

    operations = [
        migrations.AddField(
            model_name='positionqualificationmapping',
            name='grade',
            field=models.CharField(blank=True, choices=[('i', 'I'), ('ii', 'II'), ('iii', 'III'), ('iv', 'IV'), ('v', 'V')], max_length=30, null=True),
        ),
        migrations.AddField(
            model_name='positionqualificationmapping',
            name='level',
            field=models.CharField(blank=True, choices=[('i', 'I'), ('ii', 'II'), ('iii', 'III'), ('iv', 'IV')], max_length=30, null=True),
        ),
    ]
