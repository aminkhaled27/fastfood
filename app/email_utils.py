from fastapi_mail import ConnectionConfig, FastMail, MessageSchema, MessageType
from starlette.background import BackgroundTasks
from pydantic import EmailStr
from typing import List

base_url = "https://fastfood-taupe.vercel.app"
localurl = "http://127.0.0.1:8000"

conf = ConnectionConfig(
    MAIL_USERNAME = "aminkhaled004@gmail.com",
    MAIL_PASSWORD = "yclo zlvm qkip bqng",
    MAIL_FROM = "aminkhaled004@gmail.com",
    MAIL_PORT = 587,
    MAIL_SERVER = "smtp.gmail.com",
    MAIL_STARTTLS = True,
    MAIL_SSL_TLS = False,
    USE_CREDENTIALS = True,
    VALIDATE_CERTS = True
)


async def send_verification_email(email_to: EmailStr, token: str):
    """
    Sends an email with a verification link.
    This function will be run as a background task.
    """
    verification_link = f"{base_url}/auth/verify-email?token={token}"
    
    html_content = f"""
    <html>
    <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0;">

      <div style="background-color: #ff9900; color: white; padding: 15px 20px; text-align: center; font-size: 24px; font-weight: bold;">
        Fast Food
      </div>

      <div style="max-width: 600px; margin: 20px auto; padding: 30px; background-color: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); text-align: center;">
        <p style="font-size: 16px; color: #333333;">Hi,</p>
        <p style="font-size: 16px; color: #333333;">Thank you for registering. Please click the button below to verify your email address:</p>
      <div style="margin: 25px 0;">
        <a href="{verification_link}" style="background-color: #ff9900; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; font-size: 16px; display: inline-block;">Verify Email</a>
      </div>
      <p style="font-size: 14px; color: #888888;">This link is valid for 60 minutes.</p>
</div>

</body>
    </html>
    """
    
    message = MessageSchema(
        subject="Verify Your Email Address",
        recipients=[email_to],
        body=html_content,
        subtype=MessageType.html
    )

    fm = FastMail(conf)
    await fm.send_message(message)

async def send_otp_email(email_to: EmailStr, otp: str):
    html_content = f"""
    <html>
    <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0;">
      <div style="background-color: #ff9900; color: white; padding: 15px 20px; text-align: center; font-size: 24px; font-weight: bold;">
        Fast Food
      </div>
      <div style="max-width: 600px; margin: 20px auto; padding: 30px; background-color: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); text-align: center;">
        <p style="font-size: 16px; color: #333333;">Hi,</p>
        <p style="font-size: 16px; color: #333333;">Use the following One-Time Password (OTP) to reset your password:</p>
        <div style="margin: 25px 0;">
          <h2 style="font-size: 36px; color: #ff9900; letter-spacing: 5px;">{otp}</h2>
        </div>
        <p style="font-size: 14px; color: #888888;">This OTP is valid for 10 minutes.</p>
      </div>
    </body>
    </html>
    """
    message = MessageSchema(
        subject="Password Reset OTP",
        recipients=[email_to],
        body=html_content,
        subtype=MessageType.html
    )
    fm = FastMail(conf)
    await fm.send_message(message)