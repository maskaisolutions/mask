import os
from typing import Any, Dict

from google.adk.agents import Agent
from google.adk.models.lite_llm import LiteLlm

from mask import encode
from mask.integrations.adk_hooks import decrypt_before_tool, encrypt_after_tool

from .email_tool import send_secure_email

# Mock database of user profile details for testing purposes
mock_user_database = {
    "user1@example.com": {
        "name": "Mask AI Solutions",
        "role": "Security Administrator",
        "preferences": "High security mode enabled, strict audit logging.",
        "email": "user1@example.com"
    }
}


def retrieve_user_record(email: str) -> Dict[str, Any]:
    """
    Fetches the profile details for the provided user email.

    Arguments:
        email (str): The email address of the user to look up.

    Returns:
        Dict[str, Any]: A dictionary containing user traits (name, role, preferences, etc.)
    """
    # Fetch user data from our mock database
    profile = mock_user_database.get(
        email.lower(),
        {
            "name": "Unidentified User",
            "role": "Guest",
            "preferences": "No preferences set.",
            "email": email
        },
    )

    # Secure the email field by encrypting it before returning to the model's context
    profile["email"] = encode(profile["email"])
    return profile


secure_data_assistant = Agent(
    name="mask_agent",
    description="A secure agent responsible for managing contextual data for the verified session user.",
    model=LiteLlm(
        model="gpt-4o-mini",
    ),
    instruction="""You act as a data sentinel. Your primary directive is to provide accurate profile information for the actively authenticated session user, and to execute actions on their behalf if requested.
    The email address tied to the current session is provided below in the context section as a secure token.
    You must use the `retrieve_user_record` tool to extract the user's profile data in JSON format.
    If the user asks you to send them an email, you must use the `send_secure_email` tool. When calling this tool, you must exactly pass the secure email token provided in the session context. DO NOT attempt to guess the real email.
    Rely strictly on the JSON output provided by this tool to answer user inquiries about their profile traits.
    For example, if the user asks for their role, and the tool returns a 'role' field, output that value verbatim.
    If the user requests their preferences, respond with the 'preferences' text.
    If a user asks for information not present in the tool's output, firmly state: 'I am unable to provide that information.'

    Session Context:
    The current active session is bound to the email token: {user:email}.
    """,
    tools=[retrieve_user_record, send_secure_email],
    before_tool_callback=decrypt_before_tool,
    after_tool_callback=encrypt_after_tool,
)
