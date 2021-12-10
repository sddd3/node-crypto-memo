import { CryptographProcessor } from "./CryptographProcessor";

const cryptographProcessor = new CryptographProcessor();


const input = 'test';
console.log(`暗号化する文字列: ${input}`);
const result = cryptographProcessor.main(input);
console.log(`result: ${[...result]}`);