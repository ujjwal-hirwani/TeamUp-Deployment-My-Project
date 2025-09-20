import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email(sender_email, app_password, recipient_email, subject, body):
    try:
        # Create the email
        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = recipient_email
        message["Subject"] = subject

        # Attach body
        message.attach(MIMEText(body, "plain"))

        # Connect to Gmail SMTP server
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()  # Secure the connection
        server.login(sender_email, app_password)  # Login with app password

        # Send email
        server.sendmail(sender_email, recipient_email, message.as_string())
        print("✅ Email sent successfully!")

        server.quit()

    except Exception as e:
        print("❌ Error:", e)


# Example usage
if __name__ == "__main__":
    sender = "hyderabadphotos81@gmail.com"
    app_password = "krfl frbt ikcg kqod"  # Generate from Google Account > Security > App Passwords
    recipient = "ujjwalhirwani@gmail.com"
    subject = "Test Email from Python"
    body = "Hello! This is a test email sent using Python."

    send_email(sender, app_password, recipient, subject, body)
