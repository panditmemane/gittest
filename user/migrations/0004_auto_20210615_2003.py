# Generated by Django 3.1.7 on 2021-06-15 20:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0003_userprofile_is_fresher'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='userauthentication',
            name='email_otp',
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='email_token',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
    ]