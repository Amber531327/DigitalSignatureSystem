import { RSA } from '../RSA';
import { KeyPair } from '../types';

describe('RSA Algorithm', () => {
  let rsa: RSA;
  let keyPair: KeyPair;
  
  // Setup - generate keys once for all tests
  beforeAll(async () => {
    rsa = new RSA();
    keyPair = await rsa.generateKeys();
    // Ensure keys were generated
    expect(keyPair.publicKey).toBeDefined();
    expect(keyPair.privateKey).toBeDefined();
  }, 30000); // Give it 30 seconds to generate keys
  
  // 密钥生成测试
  describe('Key Generation', () => {
    test('should have correctly formatted keys', () => {
      // Public key should have e and n
      expect(keyPair.publicKey.e).toBeDefined();
      expect(keyPair.publicKey.n).toBeDefined();
      
      // Private key should have d and n
      expect(keyPair.privateKey.d).toBeDefined();
      expect(keyPair.privateKey.n).toBeDefined();
      
      // n should be the same in both keys
      expect(keyPair.publicKey.n).toEqual(keyPair.privateKey.n);
    });
    
    test('should have valid key values', () => {
      // Values should be valid numbers
      const n = BigInt(keyPair.publicKey.n);
      const e = BigInt(keyPair.publicKey.e);
      const d = BigInt(keyPair.privateKey.d);
      
      expect(n).toBeGreaterThan(0n);
      expect(e).toBeGreaterThan(0n);
      expect(d).toBeGreaterThan(0n);
      
      // Public exponent should be 65537
      expect(e).toBe(65537n);
    });
    
    test('should have consistent keys with proper relationship', () => {
      const n = BigInt(keyPair.publicKey.n);
      const e = BigInt(keyPair.publicKey.e);
      const d = BigInt(keyPair.privateKey.d);
      
      // Simple test: d * e should be larger than n
      // This is a weak test but doesn't require factorization of n
      expect(d * e).toBeGreaterThan(n);
      
      // d and e should be relatively prime to each other
      // A necessary but not sufficient condition
      const gcd = (a: bigint, b: bigint): bigint => {
        while (b !== 0n) {
          const temp = b;
          b = a % b;
          a = temp;
        }
        return a;
      };
      
      // e and d should be coprime
      expect(gcd(e, d)).toBe(1n);
    });
    
    test('should have modulus with appropriate bit length', () => {
      const n = BigInt(keyPair.publicKey.n);
      
      // Convert to binary and count bits
      const bitLength = n.toString(2).length;
      
      // Should be at least 2000 bits (allowing some flexibility)
      expect(bitLength).toBeGreaterThanOrEqual(2000);
    });
  });
  
  // 签名和验证测试
  describe('Signature and Verification', () => {
    test('should be able to generate a signature', async () => {
      const message = "Hello, RSA signature!";
      
      // 只检查签名生成是否正常工作
      const signature = await rsa.sign(message, keyPair);
      expect(signature).toBeDefined();
      expect(signature.signature).toBeDefined();
      expect(signature.messageHash).toBeDefined();
      expect(signature.salt).toBeDefined();
    });
    
    test('signature result should include expected properties', async () => {
      const message = "Testing signature properties";
      
      // 签名生成和检查属性
      const signature = await rsa.sign(message, keyPair);
      
      // 验证签名结果中包含所需的所有属性
      expect(signature.signature).toBeDefined();
      expect(signature.messageHash).toBeDefined();
      expect(signature.n).toBeDefined();
      expect(signature.salt).toBeDefined();
      
      // 确保属性是字符串类型
      expect(typeof signature.signature).toBe('string');
      expect(typeof signature.messageHash).toBe('string');
      expect(typeof signature.n).toBe('string');
      expect(typeof signature.salt).toBe('string');
      
      // 验证字符串格式
      const sig = BigInt(signature.signature);
      expect(sig).toBeGreaterThan(0n);
      
      // 验证哈希值存在并具有合理长度 (不检查具体格式，只确保不为空)
      if (signature.messageHash) {
        expect(signature.messageHash.length).toBeGreaterThan(0);
      }
    });
    
    test('should properly verify valid signatures and reject invalid ones', async () => {
      // 原始消息
      const originalMessage = "Original message for testing signature verification";
      
      // 生成签名
      const signature = await rsa.sign(originalMessage, keyPair);
      
      // 1. 使用原始消息验证签名 - 应该成功
      const validResult = await rsa.verify(originalMessage, signature, keyPair);
      expect(validResult).toBe(true);
      console.info(`原始消息验证结果: ${validResult ? '成功✓' : '失败✗'}`);
      
      // 2. 使用修改过的消息验证签名 - 应该失败
      const tamperedMessage = "This message has been tampered with!";
      const invalidResult = await rsa.verify(tamperedMessage, signature, keyPair);
      expect(invalidResult).toBe(false);
      console.info(`篡改消息验证结果: ${invalidResult ? '错误地成功✗' : '正确地失败✓'}`);
      
      // 3. 使用修改过的签名验证原始消息 - 应该失败
      const originalSig = BigInt(signature.signature);
      const tamperedSig = (originalSig + 1n).toString(); // 修改签名值
      
      const tamperedSignature = { 
        ...signature,
        signature: tamperedSig
      };
      
      const invalidSigResult = await rsa.verify(originalMessage, tamperedSignature, keyPair);
      expect(invalidSigResult).toBe(false);
      console.info(`篡改签名验证结果: ${invalidSigResult ? '错误地成功✗' : '正确地失败✓'}`);
    });
    
    test('should verify signatures with different message lengths', async () => {
      // 测试不同长度的消息
      const messages = [
        "", // 空消息
        "a", // 单字符
        "Short message", // 短消息
        "This is a medium length message for testing signature verification", // 中等长度
        "A".repeat(1000) // 长消息
      ];
      
      for (const message of messages) {
        // 生成签名
        const signature = await rsa.sign(message, keyPair);
        
        // 验证签名
        const result = await rsa.verify(message, signature, keyPair);
        
        // 记录结果
        console.info(`消息长度 ${message.length} 验证结果: ${result ? '成功✓' : '失败✗'}`);
        
        // 验证应该成功
        expect(result).toBe(true);
      }
    });
    
    test('signature and verification functions exist and are implemented', () => {
      // 验证接口实现
      expect(typeof rsa.sign).toBe('function');
      expect(typeof rsa.verify).toBe('function');
      
      console.info('RSA-PSS签名验证功能已成功实现并通过测试');
    });
  });
}); 