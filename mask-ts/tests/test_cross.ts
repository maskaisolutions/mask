import { CryptoEngine } from '../src/core/crypto';
import * as process from 'process';

async function test() {
    process.env.MASK_ENCRYPTION_KEY = "my-test-secret-key-1234567890";
    const engine = await CryptoEngine.getInstanceAsync();
    
    const ciphertext = process.argv[2];
    console.log(`DECRYPTING IN TS: ${ciphertext}`);
    const plaintext = engine.decrypt(ciphertext);
    console.log(`TS RECOVERED: ${plaintext}`);
}

test().catch(console.error);
