# Generated by Django 3.1.7 on 2021-05-29 12:03

from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='CommunicationActionType',
            fields=[
                ('created_by', models.CharField(blank=True, help_text='username', max_length=50, null=True)),
                ('updated_by', models.CharField(blank=True, help_text='username', max_length=25, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(blank=True, null=True)),
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('comm_action_type', models.CharField(blank=True, max_length=100, null=True)),
                ('is_deleted', models.BooleanField(default=False, help_text='Used for Soft Delete')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='CommunicationType',
            fields=[
                ('created_by', models.CharField(blank=True, help_text='username', max_length=50, null=True)),
                ('updated_by', models.CharField(blank=True, help_text='username', max_length=25, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(blank=True, null=True)),
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('communication_type', models.CharField(blank=True, max_length=100, null=True)),
                ('is_deleted', models.BooleanField(default=False, help_text='Used for Soft Delete')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='CommunicationMaster',
            fields=[
                ('created_by', models.CharField(blank=True, help_text='username', max_length=50, null=True)),
                ('updated_by', models.CharField(blank=True, help_text='username', max_length=25, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(blank=True, null=True)),
                ('communication_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('communication_name', models.CharField(blank=True, max_length=100, null=True)),
                ('subject', models.CharField(blank=True, max_length=200, null=True)),
                ('body', models.TextField(blank=True, null=True)),
                ('is_active', models.BooleanField(default=False)),
                ('is_deleted', models.BooleanField(default=False, help_text='Used for Soft Delete')),
                ('action_type', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='communication_action_type', to='communication_template.communicationactiontype')),
                ('comm_type', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='comm_type', to='communication_template.communicationtype')),
            ],
        ),
        migrations.AddConstraint(
            model_name='communicationmaster',
            constraint=models.UniqueConstraint(condition=models.Q(is_active=True), fields=('comm_type', 'action_type', 'is_active'), name='unique_level_per_comm_type'),
        ),
    ]
