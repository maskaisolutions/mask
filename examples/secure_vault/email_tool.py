def send_secure_email(email_address: str, subject: str, message: str) -> str:
    """
    Sends an email to the provided address (DEMO-ONLY, LEAKS PII TO STDOUT AND RESPONSES).

    This tool demonstrates the Just-In-Time Detokenization in action. The AI
    Agent will call this tool using a tokenized email address (e.g., [TKN-123]),
    but the Mask pre-hook will intercept and detokenize it back to the real
    address before this function actually executes.

    IMPORTANT/WARNING: This function deliberately prints plaintext PII (the email
    address and body) to stdout and returns raw PII for demonstration purposes.
    NEVER USE IT IN PRODUCTION. In a real system, call your email provider's SDK
    without logging sensitive fields.

    Args:
        email_address (str): The recipient's email address.
        subject (str): The subject line of the email.
        message (str): The body content of the email.

    Returns:
        str: A confirmation message of the successful email send.
    """
    print("\n[tool execution] smtplib email sender")
    print(f"Executing API request to send email to:\n----> {email_address} <----")
    print(f"Subject: {subject}")
    print(f"Body: {message}\n")
    
    return f"Successfully sent email to {email_address} with subject: '{subject}'"
