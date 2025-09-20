# utils/email_sender.py
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

def send_email(recipient_email: str, subject: str, body: str) -> None:
    sender_email = os.getenv("EMAIL_USER")
    app_password = os.getenv("EMAIL_PASS")  # Gmail App Password

    if not sender_email or not app_password:
        raise RuntimeError("EMAIL_USER/EMAIL_PASS not set in environment.")

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = recipient_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))

    server = smtplib.SMTP("smtp.gmail.com", 587)
    try:
        server.starttls()
        server.login(sender_email, app_password)
        server.sendmail(sender_email, recipient_email, message.as_string())
        print(f"✅ Email sent to {recipient_email}")
    finally:
        server.quit()
