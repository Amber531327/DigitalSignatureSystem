import { DSA } from '../DSA';
import { KeyPair } from '../types';

describe('DSA Algorithm', () => {
  let dsa: DSA;
  let keyPair: KeyPair;
  
  // Setup - generate keys once for all tests
  beforeAll(async () => {
    dsa = new DSA();
    keyPair = await dsa.generateKeys();
    // Ensure keys were generated
    expect(keyPair.publicKey).toBeDefined();
    expect(keyPair.privateKey).toBeDefined();
  }, 60000); // DSA key generation can take longer, allow 60 seconds
  
  test('should have correctly formatted keys', () => {
    // Public key
    expect(keyPair.publicKey.p).toBeDefined();
    expect(keyPair.publicKey.q).toBeDefined();
    expect(keyPair.publicKey.g).toBeDefined();
    expect(keyPair.publicKey.y).toBeDefined();
    
    // Private key
    expect(keyPair.privateKey.x).toBeDefined();
  });
  
  test('should have same domain parameters in publicKey', () => {
    // The p, q, and g parameters should be shared
    const publicP = keyPair.publicKey.p;
    const publicQ = keyPair.publicKey.q;
    const publicG = keyPair.publicKey.g;
    
    expect(publicP).toBeDefined();
    expect(publicQ).toBeDefined();
    expect(publicG).toBeDefined();
  });
  
  test('should have valid parameter values', () => {
    // Values should be valid BigInt objects
    expect(typeof keyPair.publicKey.p).toBe('bigint');
    expect(typeof keyPair.publicKey.q).toBe('bigint');
    expect(typeof keyPair.publicKey.g).toBe('bigint');
    expect(typeof keyPair.publicKey.y).toBe('bigint');
    expect(typeof keyPair.privateKey.x).toBe('bigint');
    
    // Use the BigInt values directly
    const p = keyPair.publicKey.p;
    const q = keyPair.publicKey.q;
    const g = keyPair.publicKey.g;
    const y = keyPair.publicKey.y;
    const x = keyPair.privateKey.x;
    
    expect(p).toBeGreaterThan(0n);
    expect(q).toBeGreaterThan(0n);
    expect(g).toBeGreaterThan(0n);
    expect(y).toBeGreaterThan(0n);
    expect(x).toBeGreaterThan(0n);
    
    // p should be larger than q
    expect(p).toBeGreaterThan(q);
    
    // g should be less than p
    expect(g).toBeLessThan(p);
    
    // y should be less than p
    expect(y).toBeLessThan(p);
  });
  
  test('should have parameters with appropriate bit length', () => {
    // Use the BigInt values directly
    const p = keyPair.publicKey.p;
    const q = keyPair.publicKey.q;
    
    // Convert to binary and count bits
    const pBitLength = p.toString(2).length;
    const qBitLength = q.toString(2).length;
    
    // p should be at least a 1024 bits
    expect(pBitLength).toBeGreaterThanOrEqual(1024);
    
    // q should be at least 160 bits
    expect(qBitLength).toBeGreaterThanOrEqual(160);
  });
  
  // 签名和验证测试
  describe('Signature and Verification', () => {
    test('should successfully sign and verify a message', async () => {
      const message = "Hello, DSA digital signature!";
      
      // 生成签名
      const signature = await dsa.sign(message, keyPair);
      
      // 验证签名结果包含所需属性
      expect(signature).toBeDefined();
      expect(signature.r).toBeDefined();
      expect(signature.s).toBeDefined();
      expect(signature.messageHash).toBeDefined();
      
      // 验证签名
      const result = await dsa.verify(message, signature, keyPair);
      expect(result).toBe(true);
      console.info(`原始消息验证结果: ${result ? '成功✓' : '失败✗'}`);
    });
    
    test('should return signature with expected format', async () => {
      const message = "Testing DSA signature format";
      
      const signature = await dsa.sign(message, keyPair);
      
      // 验证r和s是字符串且可解析为BigInt
      expect(typeof signature.r).toBe('string');
      expect(typeof signature.s).toBe('string');
      
      const r = BigInt(signature.r || '0');
      const s = BigInt(signature.s || '0');
      
      expect(r).toBeGreaterThan(0n);
      expect(s).toBeGreaterThan(0n);
      
      // 验证哈希值格式
      expect(typeof signature.messageHash).toBe('string');
      
      // 验证包含DSA参数位长信息
      expect(signature.pBits).toBeDefined();
      expect(signature.qBits).toBeDefined();
    });
    
    test('should reject signatures for tampered messages', async () => {
      // 原始消息
      const originalMessage = "Original message for DSA testing";
      
      // 生成签名
      const signature = await dsa.sign(originalMessage, keyPair);
      
      // 验证原始消息（应成功）
      const validResult = await dsa.verify(originalMessage, signature, keyPair);
      expect(validResult).toBe(true);
      console.info(`原始消息验证结果: ${validResult ? '成功✓' : '失败✗'}`);
      
      // 验证篡改消息（应失败）
      const tamperedMessage = "This message has been tampered with!";
      const invalidResult = await dsa.verify(tamperedMessage, signature, keyPair);
      expect(invalidResult).toBe(false);
      console.info(`篡改消息验证结果: ${invalidResult ? '错误地成功✗' : '正确地失败✓'}`);
    });
    
    test('should reject tampered signatures', async () => {
      // 原始消息
      const message = "Message for tampered signature test";
      
      // 生成签名
      const signature = await dsa.sign(message, keyPair);
      
      // 篡改签名的r值
      const originalR = BigInt(signature.r || '0');
      const tamperedR = (originalR + 1n).toString();
      
      const tamperedSignature = {
        ...signature,
        r: tamperedR
      };
      
      // 验证篡改签名（应失败）
      const result = await dsa.verify(message, tamperedSignature, keyPair);
      expect(result).toBe(false);
      console.info(`篡改r值验证结果: ${result ? '错误地成功✗' : '正确地失败✓'}`);
      
      // 篡改签名的s值
      const originalS = BigInt(signature.s || '0');
      const tamperedS = (originalS + 1n).toString();
      
      const tamperedSignature2 = {
        ...signature,
        s: tamperedS
      };
      
      // 验证篡改签名（应失败）
      const result2 = await dsa.verify(message, tamperedSignature2, keyPair);
      expect(result2).toBe(false);
      console.info(`篡改s值验证结果: ${result2 ? '错误地成功✗' : '正确地失败✓'}`);
    });
    
    test('should verify signatures with different message lengths', async () => {
      // 测试不同长度的消息
      const messages = [
        "", // 空消息
        "a", // 单字符
        "Short message", // 短消息
        "This is a medium length message for testing DSA signature verification", // 中等长度
        "A".repeat(1000) // 长消息
      ];
      
      for (const message of messages) {
        // 生成签名
        const signature = await dsa.sign(message, keyPair);
        
        // 验证签名
        const result = await dsa.verify(message, signature, keyPair);
        
        // 记录结果
        console.info(`消息长度 ${message.length} 验证结果: ${result ? '成功✓' : '失败✗'}`);
        
        // 验证应该成功
        expect(result).toBe(true);
      }
    });
    
    test('should reject signatures with invalid r or s values', async () => {
      const message = "Testing invalid signature components";
      const signature = await dsa.sign(message, keyPair);
      
      // 测试r=0（应该失败）
      const invalidR1 = {
        ...signature,
        r: "0"
      };
      expect(await dsa.verify(message, invalidR1, keyPair)).toBe(false);
      
      // 测试r=q（应该失败，r应小于q）
      const q = keyPair.publicKey.q.toString();
      const invalidR2 = {
        ...signature,
        r: q
      };
      expect(await dsa.verify(message, invalidR2, keyPair)).toBe(false);
      
      // 测试s=0（应该失败）
      const invalidS1 = {
        ...signature,
        s: "0"
      };
      expect(await dsa.verify(message, invalidS1, keyPair)).toBe(false);
      
      // 测试s=q（应该失败，s应小于q）
      const invalidS2 = {
        ...signature,
        s: q
      };
      expect(await dsa.verify(message, invalidS2, keyPair)).toBe(false);
      
      console.info('无效签名分量验证测试通过✓');
    });
  });
}); 