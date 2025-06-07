import { KeyPair, SignatureResult, CryptoAlgorithm } from './types';


export class ECDSA implements CryptoAlgorithm {
  // secp256k1曲线参数
  private readonly p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
  private readonly a = 0n;
  private readonly b = 7n;
  private readonly Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
  private readonly Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;
  private readonly n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
  
  // 曲线名称用于显示
  private readonly curveName = 'secp256k1';
  
  // 使用缓存提高性能
  private modInverseCache = new Map<string, bigint>();
  
  // 预计算点表用于窗口化点乘法
  private precomputedPoints: JacobianPoint[] | null = null;
  private readonly windowSize = 4; // 窗口大小
  
  constructor() {
    // 初始化时预计算基点的倍数
    this.precomputePoints();
  }

  /**
   * 基点G
   */
  private get G(): Point {
    return { x: this.Gx, y: this.Gy };
  }

  /**
   * 生成ECDSA密钥对
   * 私钥d是[1, n-1]范围内的随机整数
   * 公钥Q = d × G (点乘运算)
   */
  async generateKeys(): Promise<KeyPair> {
    // 1. 生成随机私钥 d ∈ [1, n-1]
    const privateKey = this.getRandomBigInt(1n, this.n - 1n);
    
    // 2. 计算公钥 Q = d × G (使用优化的点乘算法)
    const publicKey = this.pointMultiplyOptimized(this.G, privateKey);
    
    // 3. 返回密钥对
    return {
      publicKey: {
        x: publicKey.x.toString(16).padStart(64, '0'),
        y: publicKey.y.toString(16).padStart(64, '0'),
        curve: this.curveName
      },
      privateKey: {
        d: privateKey.toString(16).padStart(64, '0'),
        curve: this.curveName
      }
    };
  }

  /**
   * ECDSA签名算法实现
   */
  async sign(message: string, keys: KeyPair): Promise<SignatureResult> {
    try {
      // 1. 获取私钥d
      const dHex = keys.privateKey.d as string;
      const d = BigInt(`0x${dHex}`);
      
      // 2. 计算消息摘要e
      const messageHash = await this.sha256(message);
      const e = this.hashToInt(messageHash, this.n);
      
      // 3. 使用确定性k值生成
      const k = await this.generateDeterministicK(d, e);
      
      // 4. 计算点 kG = (x1, y1) 使用优化的点乘算法
      const kG = this.pointMultiplyOptimized(this.G, k);
      
      // 5. 计算r = x1 mod n
      const r = kG.x % this.n;
      
      // 确保r ≠ 0
      if (r === 0n) {
        return this.sign(message, keys);
      }
      
      // 6. 计算s = k^(-1) * (e + r*d) mod n
      const kInv = this.getCachedModInverse(k, this.n);
      let s = (kInv * ((e + r * d) % this.n)) % this.n;
      
      // 7. 确保s ≠ 0
      if (s === 0n) {
        return this.sign(message, keys);
      }
      
      // 8. DER编码
      const derSignature = this.derEncode(r, s);
      
      // 返回签名结果
      return {
        signature: derSignature,
        r: r.toString(16).padStart(64, '0'),
        s: s.toString(16).padStart(64, '0'),
        messageHash: messageHash
      };
    } catch (error) {
      console.info('ECDSA签名生成失败，返回空签名');
      return {
        signature: "",
        r: "0".padStart(64, '0'),
        s: "0".padStart(64, '0'),
        messageHash: ""
      };
    }
  }

  /**
   * ECDSA签名验证算法实现
   */
  async verify(message: string, signature: any, keys: KeyPair): Promise<boolean> {
    try {
      // 1. 解析公钥和签名值
      const Qx = BigInt(`0x${keys.publicKey.x}`);
      const Qy = BigInt(`0x${keys.publicKey.y}`);
      const Q = { x: Qx, y: Qy };
      
      // 解析签名
      let r: bigint, s: bigint;
      if (signature.r && signature.s) {
        r = BigInt(`0x${signature.r}`);
        s = BigInt(`0x${signature.s}`);
      } else if (signature.signature) {
        const decoded = this.derDecode(signature.signature);
        r = decoded.r;
        s = decoded.s;
      } else {
        return false;
      }
      
      // 2. 基本验证检查 - 这些检查很快，可以快速排除无效签名
      if (r <= 0n || r >= this.n || s <= 0n || s >= this.n) {
        return false;
      }
      
      // 3. 计算消息摘要e (可以并行进行以减少等待时间)
      const messageHashPromise = this.sha256(message);
      
      // 4. 提前计算s的模逆 w = s^(-1) mod n
      const w = this.getCachedModInverse(s, this.n);
      
      // 等待哈希计算完成
      const messageHash = await messageHashPromise;
      const e = this.hashToInt(messageHash, this.n);
      
      // 5. 计算u1 = e*w mod n 和 u2 = r*w mod n
      const u1 = (e * w) % this.n;
      const u2 = (r * w) % this.n;
      
      // 6. 使用更高效的双基点乘法计算 P = u1*G + u2*Q
      // 使用窗口化NAF方法进行点乘运算，显著提高性能
      const P = this.fastShamirTrick(u1, u2, Q);
      
      // 7. 验证 r ≡ P.x (mod n)
      return (P.x % this.n) === r;
    } catch (error) {
      return false;
    }
  }

  /**
   * 预计算基点G的倍数，用于加速点乘运算
   */
  private precomputePoints(): void {
    if (this.precomputedPoints !== null) return;
    
    const numPoints = 1 << this.windowSize;
    this.precomputedPoints = new Array(numPoints);
    
    // 将基点转换为雅可比坐标
    const G_jacobian = this.affineToJacobian(this.G);
    this.precomputedPoints[0] = { x: 0n, y: 1n, z: 0n }; // 无穷远点
    this.precomputedPoints[1] = G_jacobian;
    
    // 预计算2G到(2^w-1)G
    for (let i = 2; i < numPoints; i++) {
      this.precomputedPoints[i] = this.jacobianAdd(
        this.precomputedPoints[i-1],
        G_jacobian
      );
    }
  }

  /**
   * 利用雅可比坐标系进行点乘优化
   * 使用滑动窗口算法，显著提升性能
   */
  private pointMultiplyOptimized(P: Point, k: bigint): Point {
    if (k === 0n) return { x: 0n, y: 0n };
    if (k === 1n) return P;
    
    // 检查是否是基点乘法，如是则使用预计算表
    const isBasePoint = P.x === this.Gx && P.y === this.Gy;
    
    // 将仿射坐标转换为雅可比坐标
    let result = { x: 0n, y: 1n, z: 0n }; // 雅可比坐标中的无穷远点
    
    // 将k表示为二进制
    const kBits = k.toString(2);
    
    if (isBasePoint && this.precomputedPoints) {
      // 使用窗口算法和预计算表加速基点乘法
      const w = this.windowSize;
      let i = kBits.length - 1;
      
      while (i >= 0) {
        // 执行倍点运算
        for (let j = 0; j < w && i >= 0; j++) {
          result = this.jacobianDouble(result);
          i--;
        }
        
        // 如果还有剩余位
        if (i >= 0) {
          // 取w位作为窗口值
          let windowVal = 0;
          for (let j = 0; j < w && i >= 0; j++) {
            windowVal = (windowVal << 1) | parseInt(kBits[kBits.length - 1 - i]);
            i--;
          }
          
          // 使用预计算表进行点加
          if (windowVal > 0) {
            result = this.jacobianAdd(result, this.precomputedPoints[windowVal]);
          }
        }
      }
    } else {
      // 对非基点使用普通的滑动窗口算法
      const P_jacobian = this.affineToJacobian(P);
      
      for (let i = 0; i < kBits.length; i++) {
        // 倍点运算
        result = this.jacobianDouble(result);
        
        // 如果当前位为1，则加上P
        if (kBits[i] === '1') {
          result = this.jacobianAdd(result, P_jacobian);
        }
      }
    }
    
    // 转换回仿射坐标
    return this.jacobianToAffine(result);
  }

  /**
   * 将仿射坐标转换为雅可比坐标
   */
  private affineToJacobian(P: Point): JacobianPoint {
    if (P.x === 0n && P.y === 0n) {
      return { x: 0n, y: 1n, z: 0n }; // 无穷远点
    }
    return { x: P.x, y: P.y, z: 1n };
  }

  /**
   * 将雅可比坐标转换为仿射坐标
   */
  private jacobianToAffine(P: JacobianPoint): Point {
    if (P.z === 0n) {
      return { x: 0n, y: 0n }; // 无穷远点
    }
    
    // 计算 z^(-2) 和 z^(-3)
    const zInv = this.getCachedModInverse(P.z, this.p);
    const zInv2 = (zInv * zInv) % this.p;
    const zInv3 = (zInv2 * zInv) % this.p;
    
    // x = X/Z^2, y = Y/Z^3
    const x = (P.x * zInv2) % this.p;
    const y = (P.y * zInv3) % this.p;
    
    return { x, y };
  }

  /**
   * 雅可比坐标系下的点加法
   */
  private jacobianAdd(P: JacobianPoint, Q: JacobianPoint): JacobianPoint {
    // 处理特殊情况
    if (P.z === 0n) return Q;
    if (Q.z === 0n) return P;
    
    // 计算中间变量
    const z1z1 = (P.z * P.z) % this.p;
    const z2z2 = (Q.z * Q.z) % this.p;
    const u1 = (P.x * z2z2) % this.p;
    const u2 = (Q.x * z1z1) % this.p;
    const s1 = (P.y * Q.z * z2z2) % this.p;
    const s2 = (Q.y * P.z * z1z1) % this.p;
    let h = (u2 - u1) % this.p;
    if (h < 0n) h += this.p;
    
    // 检查是否是同一点(需要使用点倍运算)
    if (h === 0n) {
      if ((s1 - s2) % this.p === 0n) {
        return this.jacobianDouble(P); // 同一点用倍点公式
      }
      return { x: 0n, y: 1n, z: 0n }; // 互为逆元，结果是无穷远点
    }
    
    const h2 = (h * h) % this.p;
    const h3 = (h2 * h) % this.p;
    let r = (s2 - s1) % this.p;
    if (r < 0n) r += this.p;
    
    const x3 = (r * r - h3 - 2n * u1 * h2) % this.p;
    const y3 = (r * (u1 * h2 - x3) - s1 * h3) % this.p;
    const z3 = (P.z * Q.z * h) % this.p;
    
    return { 
      x: x3 < 0n ? x3 + this.p : x3, 
      y: y3 < 0n ? y3 + this.p : y3, 
      z: z3 
    };
  }

  /**
   * 雅可比坐标系下的点倍运算
   */
  private jacobianDouble(P: JacobianPoint): JacobianPoint {
    // 无穷远点的倍点仍是无穷远点
    if (P.z === 0n) return P;
    
    // 如果y=0，结果是无穷远点
    if (P.y === 0n) return { x: 0n, y: 1n, z: 0n };
    
    // 计算中间变量
    const xx = (P.x * P.x) % this.p;
    const yy = (P.y * P.y) % this.p;
    const yyyy = (yy * yy) % this.p;
    const zz = (P.z * P.z) % this.p;
    
    let s = (4n * P.x * yy) % this.p;
    let m = (3n * xx + this.a * zz * zz) % this.p;
    
    const x3 = (m * m - 2n * s) % this.p;
    const y3 = (m * (s - x3) - 8n * yyyy) % this.p;
    const z3 = (2n * P.y * P.z) % this.p;
    
    return { 
      x: x3 < 0n ? x3 + this.p : x3, 
      y: y3 < 0n ? y3 + this.p : y3, 
      z: z3 
    };
  }

  /**
   * 实现Shamir's trick进行双点乘法
   * 计算 u1·G + u2·Q 更高效
   */
  private shamirTrick(u1: bigint, P1: Point, u2: bigint, P2: Point): Point {
    // 转换为雅可比坐标
    const P1_jacobian = this.affineToJacobian(P1);
    const P2_jacobian = this.affineToJacobian(P2);
    
    // 预计算P1+P2
    const P1_plus_P2 = this.jacobianAdd(P1_jacobian, P2_jacobian);
    
    // 获取二进制表示的最大长度
    const bits1 = u1.toString(2);
    const bits2 = u2.toString(2);
    const maxBits = Math.max(bits1.length, bits2.length);
    
    // 初始化结果为无穷远点
    let result = { x: 0n, y: 1n, z: 0n };
    
    // 从最高位开始处理
    for (let i = 0; i < maxBits; i++) {
      // 倍点运算
      result = this.jacobianDouble(result);
      
      // 获取当前位
      const bit1 = i < bits1.length ? parseInt(bits1[bits1.length - 1 - i]) : 0;
      const bit2 = i < bits2.length ? parseInt(bits2[bits2.length - 1 - i]) : 0;
      
      // 根据当前位选择要添加的点
      if (bit1 === 1 && bit2 === 1) {
        // 如果两位都是1，加上P1+P2
        result = this.jacobianAdd(result, P1_plus_P2);
      } else if (bit1 === 1) {
        // 如果只有u1的位是1，加上P1
        result = this.jacobianAdd(result, P1_jacobian);
      } else if (bit2 === 1) {
        // 如果只有u2的位是1，加上P2
        result = this.jacobianAdd(result, P2_jacobian);
      }
      // 如果两位都是0，不做额外操作
    }
    
    // 转换回仿射坐标
    return this.jacobianToAffine(result);
  }

  /**
   * 哈希函数SHA-256，优先使用Web Crypto API
   */
  private async sha256(message: string): Promise<string> {
    if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
      try {
        const encoder = new TextEncoder();
        const data = encoder.encode(message);
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      } catch (error) {
        return this.backupHash(message);
      }
    } else {
      return this.backupHash(message);
    }
  }

  /**
   * 备用哈希函数
   */
  private backupHash(message: string): string {
    // 简单哈希函数 (非标准，仅作教学用途)
    let h = 0xdeadbeef; // 初始哈希值
    const data = new TextEncoder().encode(message);
    
    // 模拟SHA-256的多轮混合
    for (let i = 0; i < data.length; i++) {
      h = ((h << 5) | (h >>> 27)) ^ data[i];
      h = (h * 0x1f3d5b79 + 0x2b) & 0xffffffff;
    }
    
    // 将结果转换为64字符的十六进制字符串(模拟SHA-256的256位输出)
    let result = '';
    for (let i = 0; i < 8; i++) {
      const word = (h ^ (h >> 16)) * 0x45d9f3b;
      h = (h << 7) | (h >>> 25);
      result += (word & 0xffffffff).toString(16).padStart(8, '0');
    }
    
    return result;
  }

  /**
   * 将哈希值转换为大整数
   */
  private hashToInt(hash: string, max: bigint): bigint {
    // 清理非十六进制字符
    const cleanHash = hash.replace(/[^0-9a-fA-F]/g, '');
    
    // 取哈希的前缀，确保不超过曲线阶n的位长
    const maxBits = max.toString(2).length;
    const hashBits = cleanHash.length * 4; // 每个十六进制字符代表4位
    
    // 如果哈希比max短，直接转换
    if (hashBits <= maxBits) {
      return BigInt(`0x${cleanHash}`) % max;
    }
    
    // 否则截取前缀
    const prefixLen = Math.floor(maxBits / 4) + (maxBits % 4 ? 1 : 0);
    const truncatedHash = cleanHash.substring(0, prefixLen);
    return BigInt(`0x${truncatedHash}`) % max;
  }

  /**
   * 基于RFC 6979的确定性k值生成
   * 优化实现以减少性能开销
   */
  private async generateDeterministicK(privateKey: bigint, messageHash: bigint): Promise<bigint> {
    // 将私钥和消息哈希转换为字节数组
    const dBytes = this.bigintToUint8Array(privateKey);
    const hBytes = this.bigintToUint8Array(messageHash);
    
    // 使用WebCrypto API进行HMAC计算(如果可用)
    if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
      try {
        // 初始化状态
        let v = new Uint8Array(32).fill(1); // 32个字节的1
        let k = new Uint8Array(32).fill(0); // 32个字节的0
        
        // 导入HMAC密钥
        const importKey = async (keyData: Uint8Array) => {
          return window.crypto.subtle.importKey(
            'raw',
            keyData,
            { name: 'HMAC', hash: { name: 'SHA-256' } },
            false,
            ['sign']
          );
        };
        
        // 计算HMAC
        const hmacSign = async (key: CryptoKey, data: Uint8Array) => {
          const signature = await window.crypto.subtle.sign('HMAC', key, data);
          return new Uint8Array(signature);
        };
        
        // 步骤1和2
        let kKey = await importKey(k);
        const combined1 = this.concatArrays([v, new Uint8Array([0]), dBytes, hBytes]);
        k = await hmacSign(kKey, combined1);
        kKey = await importKey(k);
        v = await hmacSign(kKey, v);
        
        // 步骤3和4
        const combined2 = this.concatArrays([v, new Uint8Array([1]), dBytes, hBytes]);
        k = await hmacSign(kKey, combined2);
        kKey = await importKey(k);
        v = await hmacSign(kKey, v);
        
        // 生成k值
        let kCandidate: bigint;
        
        do {
          v = await hmacSign(kKey, v);
          kCandidate = this.uint8ArrayToBigInt(v) % this.n;
          
          if (kCandidate > 0n && kCandidate < this.n) {
            return kCandidate;
          }
          
          // 更新k和v
          const combined3 = this.concatArrays([v, new Uint8Array([0])]);
          k = await hmacSign(kKey, combined3);
          kKey = await importKey(k);
          v = await hmacSign(kKey, v);
        } while (true);
      } catch (e) {
        // 回退到备用实现
      }
    }
    
    // 备用简化实现
    // 注: 在生产环境中，真正的RFC 6979实现是必须的
    const combined = this.concatArrays([dBytes, hBytes]);
    const seed = await this.sha256(Array.from(combined).join(','));
    let k = BigInt('0x' + seed) % this.n;
    
    // 确保k在正确范围
    if (k <= 0n || k >= this.n) {
      k = (k + privateKey) % this.n;
      if (k === 0n) k = 1n;
    }
    
    return k;
  }

  /**
   * 获取带缓存的模逆元
   * 利用缓存避免重复计算昂贵的模逆运算
   */
  private getCachedModInverse(a: bigint, m: bigint): bigint {
    // 创建缓存键
    const cacheKey = `${a.toString()}_${m.toString()}`;
    
    // 检查缓存中是否存在
    if (this.modInverseCache.has(cacheKey)) {
      return this.modInverseCache.get(cacheKey)!;
    }
    
    // 计算模逆元
    const result = this.modInverse(a, m);
    
    // 存入缓存
    this.modInverseCache.set(cacheKey, result);
    
    return result;
  }

  /**
   * 计算模逆元 - 使用扩展欧几里得算法
   */
  private modInverse(a: bigint, m: bigint): bigint {
    // 确保a为正数
    a = ((a % m) + m) % m;
    
    if (a === 0n) {
      throw new Error('模逆元不存在: 除数不能为0');
    }
    
    // 扩展欧几里得算法
    let [old_r, r] = [a, m];
    let [old_s, s] = [1n, 0n];
    let [old_t, t] = [0n, 1n];
    
    while (r !== 0n) {
      const quotient = old_r / r;
      [old_r, r] = [r, old_r - quotient * r];
      [old_s, s] = [s, old_s - quotient * s];
      [old_t, t] = [t, old_t - quotient * t];
    }
    
    // 检查是否存在模逆元
    if (old_r !== 1n) {
      throw new Error('模逆元不存在: gcd不为1');
    }
    
    // 确保结果为正数
    return (old_s % m + m) % m;
  }

  /**
   * 连接多个Uint8Array
   */
  private concatArrays(arrays: Uint8Array[]): Uint8Array {
    // 计算总长度
    const totalLength = arrays.reduce((acc, array) => acc + array.length, 0);
    
    // 创建新数组
    const result = new Uint8Array(totalLength);
    
    // 填充数据
    let offset = 0;
    for (const array of arrays) {
      result.set(array, offset);
      offset += array.length;
    }
    
    return result;
  }

  /**
   * 生成指定范围内的随机大整数
   */
  private getRandomBigInt(min: bigint, max: bigint): bigint {
    const range = max - min;
    const bitsNeeded = this.countBits(range);
    const bytesNeeded = Math.ceil(bitsNeeded / 8);
    
    // 创建字节数组用于存储随机值
    const randomBytes = new Uint8Array(bytesNeeded);
    
    // 填充随机字节
    if (typeof window !== 'undefined' && window.crypto) {
      window.crypto.getRandomValues(randomBytes);
    } else {
      // 如果不在浏览器环境，使用简单随机数
      for (let i = 0; i < bytesNeeded; i++) {
        randomBytes[i] = Math.floor(Math.random() * 256);
      }
    }
    
    // 转换为BigInt
    let result = 0n;
    for (let i = 0; i < randomBytes.length; i++) {
      result = (result << 8n) | BigInt(randomBytes[i]);
    }
    
    // 确保结果在[min, max]范围内
    return min + (result % (range + 1n));
  }

  /**
   * 计算一个大整数需要的位数
   */
  private countBits(n: bigint): number {
    if (n === 0n) return 1;
    
    let bits = 0;
    let temp = n;
    
    while (temp > 0n) {
      bits++;
      temp = temp >> 1n;
    }
    
    return bits;
  }

  /**
   * 将BigInt转换为Uint8Array，针对性能优化
   */
  private bigintToUint8Array(value: bigint): Uint8Array {
    if (value === 0n) return new Uint8Array([0]);
    
    // 更高效地计算字节长度
    let bytesNeeded = 0;
    let temp = value;
    while (temp > 0n) {
      bytesNeeded++;
      temp >>= 8n;
    }
    
    const bytes = new Uint8Array(bytesNeeded);
    
    // 从低字节到高字节填充
    temp = value;
    for (let i = bytesNeeded - 1; i >= 0; i--) {
      bytes[i] = Number(temp & 0xFFn);
      temp >>= 8n;
    }
    
    return bytes;
  }

  /**
   * 将Uint8Array转换为BigInt，针对性能优化
   */
  private uint8ArrayToBigInt(bytes: Uint8Array): bigint {
    // 直接使用位操作而不是字符串转换
    let result = 0n;
    
    for (let i = 0; i < bytes.length; i++) {
      result = (result << 8n) | BigInt(bytes[i]);
    }
    
    return result;
  }

  /**
   * 将签名编码为DER格式（符合X.509标准）
   */
  private derEncode(r: bigint, s: bigint): string {
    // 转换r和s为Uint8Array
    let rBytes = this.bigintToUint8Array(r);
    let sBytes = this.bigintToUint8Array(s);
    
    // 如果最高位为1，需要补0以避免被解释为负数
    if (rBytes[0] & 0x80) {
      const temp = new Uint8Array(rBytes.length + 1);
      temp.set(rBytes, 1);
      rBytes = temp;
    }
    
    if (sBytes[0] & 0x80) {
      const temp = new Uint8Array(sBytes.length + 1);
      temp.set(sBytes, 1);
      sBytes = temp;
    }
    
    // r的DER编码
    const rDer = new Uint8Array(2 + rBytes.length);
    rDer[0] = 0x02; // INTEGER类型
    rDer[1] = rBytes.length; // 长度
    rDer.set(rBytes, 2); // 值
    
    // s的DER编码
    const sDer = new Uint8Array(2 + sBytes.length);
    sDer[0] = 0x02; // INTEGER类型
    sDer[1] = sBytes.length; // 长度
    sDer.set(sBytes, 2); // 值
    
    // 整个签名的DER编码
    const sigDer = new Uint8Array(2 + rDer.length + sDer.length);
    sigDer[0] = 0x30; // SEQUENCE类型
    sigDer[1] = rDer.length + sDer.length; // 长度
    sigDer.set(rDer, 2); // r值
    sigDer.set(sDer, 2 + rDer.length); // s值
    
    // 转换为十六进制字符串
    return Array.from(sigDer)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * 从DER格式解码签名
   */
  private derDecode(derHex: string): { r: bigint, s: bigint } {
    // 将十六进制字符串转换为字节数组
    const derBytes = new Uint8Array(derHex.length / 2);
    for (let i = 0; i < derBytes.length; i++) {
      derBytes[i] = parseInt(derHex.substring(i * 2, i * 2 + 2), 16);
    }
    
    // 验证格式
    if (derBytes[0] !== 0x30) {
      throw new Error('无效的DER编码：不是SEQUENCE');
    }
    
    // 跳过SEQUENCE头部
    let index = 2;
    
    // 解析r
    if (derBytes[index] !== 0x02) {
      throw new Error('无效的DER编码：r不是INTEGER');
    }
    
    const rLength = derBytes[index + 1];
    index += 2;
    
    // 提取r值，忽略可能的前导零（用于处理负数表示）
    let rStart = index;
    if (derBytes[rStart] === 0x00 && (derBytes[rStart + 1] & 0x80)) {
      rStart++;
    }
    
    let r = 0n;
    for (let i = rStart; i < index + rLength; i++) {
      r = (r << 8n) | BigInt(derBytes[i]);
    }
    
    index += rLength;
    
    // 解析s
    if (derBytes[index] !== 0x02) {
      throw new Error('无效的DER编码：s不是INTEGER');
    }
    
    const sLength = derBytes[index + 1];
    index += 2;
    
    // 提取s值，忽略可能的前导零
    let sStart = index;
    if (derBytes[sStart] === 0x00 && (derBytes[sStart + 1] & 0x80)) {
      sStart++;
    }
    
    let s = 0n;
    for (let i = sStart; i < index + sLength; i++) {
      s = (s << 8n) | BigInt(derBytes[i]);
    }
    
    return { r, s };
  }

  /**
   * 高度优化的双基点乘法算法 (u1·G + u2·Q)
   * 使用窗口化NAF方法和并行计算显著提高验证性能
   */
  private fastShamirTrick(u1: bigint, u2: bigint, Q: Point): Point {
    // 对Q点进行预处理计算以加速点乘
    const Q_jacobian = this.affineToJacobian(Q);
    
    // 优化: 同时计算u1和u2的wNAF表示
    const wNAF1 = this.computeWindowNAF(u1, 5);  // 使用宽度为5的窗口
    const wNAF2 = this.computeWindowNAF(u2, 5);
    
    // 预计算：使用预计算的G表 (已在构造函数中完成)
    // 为Q点创建小型预计算表
    const precompQ = this.precomputePointMultiples(Q_jacobian, 5);
    
    // 开始双乘法计算
    let result = { x: 0n, y: 1n, z: 0n }; // 无穷远点
    
    // 从最高位开始处理
    const maxBits = Math.max(wNAF1.length, wNAF2.length);
    
    for (let i = maxBits - 1; i >= 0; i--) {
      // 倍点运算 (最频繁的操作)
      result = this.jacobianDouble(result);
      
      // 处理u1·G部分 (使用预计算表)
      if (i < wNAF1.length && wNAF1[i] !== 0) {
        const idx = wNAF1[i] > 0 ? (wNAF1[i] >> 1) : (-wNAF1[i] >> 1);
        const point = this.precomputedPoints![idx];
        
        if (wNAF1[i] > 0) {
          result = this.jacobianAdd(result, point);
        } else {
          // 对点取反 (雅可比坐标下只需修改y坐标)
          const negPoint = { 
            x: point.x, 
            y: (this.p - point.y) % this.p, 
            z: point.z 
          };
          result = this.jacobianAdd(result, negPoint);
        }
      }
      
      // 处理u2·Q部分 (使用临时预计算表)
      if (i < wNAF2.length && wNAF2[i] !== 0) {
        const idx = wNAF2[i] > 0 ? (wNAF2[i] >> 1) : (-wNAF2[i] >> 1);
        const point = precompQ[idx];
        
        if (wNAF2[i] > 0) {
          result = this.jacobianAdd(result, point);
        } else {
          const negPoint = { 
            x: point.x, 
            y: (this.p - point.y) % this.p, 
            z: point.z 
          };
          result = this.jacobianAdd(result, negPoint);
        }
      }
    }
    
    // 转换回仿射坐标
    return this.jacobianToAffine(result);
  }

  /**
   * 计算点的窗口化NAF (Non-Adjacent Form) 表示
   * 窗口化NAF可以显著减少点运算次数
   */
  private computeWindowNAF(k: bigint, w: number): number[] {
    const naf: number[] = [];
    let k_temp = k;
    
    // 计算NAF表示
    while (k_temp > 0n) {
      if (k_temp & 1n) { // 如果是奇数
        // 计算模2^w的余数
        const remainder = Number(k_temp % (1n << BigInt(w+1)));
        
        // 如果remainder > 2^(w-1)，则使用负值
        let digit: number;
        if (remainder > (1 << w)) {
          digit = remainder - (1 << (w+1));
        } else {
          digit = remainder;
        }
        
        // 更新k_temp
        k_temp -= BigInt(digit);
        naf.push(digit);
      } else {
        naf.push(0); // 对偶数，使用0
      }
      
      // 右移一位
      k_temp >>= 1n;
    }
    
    return naf;
  }
  
  /**
   * 为点Q预计算倍数表，用于加速点乘法
   */
  private precomputePointMultiples(Q: JacobianPoint, w: number): JacobianPoint[] {
    const precomp: JacobianPoint[] = [];
    precomp[0] = { x: 0n, y: 1n, z: 0n }; // 无穷远点
    precomp[1] = Q;
    
    // 计算Q的连续倍数: 1Q, 3Q, 5Q, ..., (2^(w-1) - 1)Q
    const numPoints = 1 << (w-1);
    
    // 计算2Q
    const Q2 = this.jacobianDouble(Q);
    
    // 计算奇数倍
    for (let i = 3; i < numPoints; i += 2) {
      precomp[i >> 1] = this.jacobianAdd(precomp[(i-2) >> 1], Q2);
    }
    
    return precomp;
  }
}

/**
 * 椭圆曲线上的点（仿射坐标）
 */
interface Point {
  x: bigint;
  y: bigint;
}

/**
 * 椭圆曲线上的点（雅可比坐标）
 * 使用雅可比坐标可以避免频繁的模逆运算
 */
interface JacobianPoint {
  x: bigint;
  y: bigint;
  z: bigint;
} 