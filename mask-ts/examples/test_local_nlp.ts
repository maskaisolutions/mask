import { ascanAndTokenize, detectEntitiesWithConfidence } from '../src/index';

async function main() {
    const text = "My name is Alice and I live in San Francisco. My email is alice@example.com and my phone is 555-123-4567.";
    
    console.log("Input Text:", text);
    console.log("\nDetecting entities...");
    
    try {
        const entities = await detectEntitiesWithConfidence(text);
        console.log("Detected Entities:", JSON.stringify(entities, null, 2));

        console.log("\nMasking text...");
        const masked = await ascanAndTokenize(text);
        console.log("Masked Text:", masked);
    } catch (e) {
        console.error("Error during NLP scan:", e);
    }
}

main();
