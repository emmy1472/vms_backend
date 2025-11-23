import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Attachment
import base64

SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
DEFAULT_FROM_EMAIL = "emmanuelakinmolayan1@gmail.com"   # replace with yours


def send_email_sendgrid(subject, html_content, to_email, attachments=None):
    """
    attachments: list of dicts:
    [
        {
            "content": bytes,
            "filename": "qr.png",
            "type": "image/png"
        }
    ]
    """

    message = Mail(
        from_email=DEFAULT_FROM_EMAIL,
        to_emails=to_email,
        subject=subject,
        html_content=html_content,
    )

    # Handle attachments (QR code)
    if attachments:
        for att in attachments:
            encoded_file = base64.b64encode(att["content"]).decode()
            attached = Attachment(
                file_content=encoded_file,
                file_type=att["type"],
                file_name=att["filename"],
                disposition="attachment"
            )
            message.attachment = attached

    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        return response.status_code
    except Exception as e:
        print("SendGrid error:", str(e))
        return None
