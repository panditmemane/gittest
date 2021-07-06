import http.client
from django.core.mail import send_mail
from communication_template.models import CommunicationMaster
from neeri_recruitment_portal import settings
from neeri_recruitment_portal.settings import BASE_URL, BASE_DEV_URL


def send_otp(mobile, otp):  # /verify_mobile/
    conn = http.client.HTTPSConnection("api.msg91.com")
    authkey = settings.AUTH_KEY
    senderid = "NEERIC"
    print("senderid---->", senderid)

    route = settings.ROUTE
    countrycode = settings.COUNTRY_CODE
    headers = {'content-type': "application/json"}
    # url = "http://control.msg91.com/api/sendotp.php?otp="+otp+"&message="+"Your otp is "+otp +"&mobile="+mobile+"&authkey="+authkey+"&country=91"
    url = "/api/v2/sendsms?authkey="+authkey+"&mobiles="+mobile+"&message=Your OTP for Verification is "+ otp +"&sender="+senderid+"&route="+route+"&country="+countrycode+""
    print("url---->", url)
    conn.request("GET", url, headers=headers)
    res = conn.getresponse()
    data = res.read()
    print(data)
    print("OTP sent")
    return None


def send_verification_mail(email, email_token):
    template = CommunicationMaster.objects.filter(comm_type__communication_type='EMAIL',
                                                  action_type__comm_action_type='VERIFY EMAIL', is_active=True).first()
    subject = template.subject
    message = template.body + "\n" + BASE_DEV_URL + f'/verify_email/{email_token}/\n\n' \
                                                   f'Regards,\nNEERI Recruitment Team'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(
        subject,
        message,
        email_from,
        recipient_list,
        fail_silently=False
    )
    print("email sent")
    return None



def send_forget_password_mail(email , token ):
    template = CommunicationMaster.objects.filter(comm_type__communication_type='EMAIL',
                                                  action_type__comm_action_type='FORGOT PASSWORD', is_active=True).first()
    subject = template.subject
    message = template.body+" " + BASE_DEV_URL + f'/reset_password/{token}/'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list)
    return True


def send_password_mail(email, password):
    template = CommunicationMaster.objects.filter(comm_type__communication_type='EMAIL',
                                                  action_type__comm_action_type='CHANGE PASSWORD',
                                                  is_active=True).first()
    subject = template.subject
    message = template.body + f' {password}.\n' + BASE_DEV_URL + f'/admin/'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(
        subject,
        message,
        email_from,
        recipient_list,
        fail_silently=False
    )
    print("email sent")
    return None