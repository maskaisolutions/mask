export function sendSecureEmail(emailAddress: string, subject: string, message: string): string {
    /**
     * Sends an email to the provided address (DEMO-ONLY, LELeaks PII TO STDOUT AND RESPONSES).
     *
     * This tool demonstrates the Just-In-Time Detokenization in action. 
     */
    console.log("\n[tool execution] smtplib email sender");
    console.log(`Executing API request to send email to:\n----> ${emailAddress} <----`);
    console.log(`Subject: ${subject}`);
    console.log(`Body: ${message}\n`);
    
    return `Successfully sent email to ${emailAddress} with subject: '${subject}'`;
}
