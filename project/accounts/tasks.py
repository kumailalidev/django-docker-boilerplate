from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model

from .utils import send_mail

from celery import shared_task

UserModel = get_user_model()


@shared_task
def user_created(user_id, email_context):
    """
    Task to send an e-mail notification when an user account
    is successfully created.
    """
    email_field_name = UserModel.get_email_field_name()
    user = get_object_or_404(UserModel, id=user_id)
    user_email = getattr(user, email_field_name)

    context = {
        **email_context,
        "user": user,
    }

    send_mail(
        subject_template_name="registration/user_created_email_subject.txt",
        email_template_name="registration/user_created_email.html",
        context=context,
        from_email=None,
        to_email=user_email,
        html_email_template_name="registration/user_created_email.html",
    )
