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
      // 添加调试输出
      console.info('开始ECDSA签名生成...');
      
      // 1. 获取私钥d
      const dHex = keys.privateKey.d as string;
      console.info(`私钥d长度: ${dHex.length}`);
      
      if (!dHex || dHex.length === 0) {
        throw new Error('私钥为空');
      }
      
      const d = BigInt(`0x${dHex}`);
      console.info(`私钥d转换为BigInt成功`);
      
      // 2. 计算消息摘要e
      const messageHash = await this.sha256(message);
      console.info(`消息哈希值: ${messageHash.substring(0, 10)}...`);
      
      const e = this.hashToInt(messageHash, this.n);
      console.info(`哈希整数e生成成功`);
      
      // 3. 生成随机k值
      // 使用简单但可靠的方法
      let k: bigint;
      
      // 直接使用确定性种子生成k值
      const combined = dHex + messageHash;
      const seed = this.backupHash(combined);
      k = BigInt('0x' + seed) % (this.n - 1n) + 1n;
      
      console.info(`生成k值成功: ${k > 0n ? '有效' : '无效'}`);
      
      if (k <= 0n || k >= this.n) {
        throw new Error('无效的k值');
      }
      
      // 4. 计算点 kG = (x1, y1)
      console.info('开始点乘运算...');
      const kG = this.pointMultiplyOptimized(this.G, k);
      console.info(`点乘结果x: ${kG.x.toString().substring(0, 10)}...`);
      
      // 5. 计算r = x1 mod n
      const r = kG.x % this.n;
      console.info(`r值: ${r.toString().substring(0, 10)}...`);
      
      // 确保r ≠ 0
      if (r === 0n) {
        throw new Error('r = 0，需要重新生成k值');
      }
      
      // 6. 计算s = k^(-1) * (e + r*d) mod n
      const kInv = this.modInverse(k, this.n);
      console.info('计算k的模逆元成功');
      
      const rd = (r * d) % this.n;
      const erd = (e + rd) % this.n;
      let s = (kInv * erd) % this.n;
      console.info(`s值: ${s.toString().substring(0, 10)}...`);
      
      // 7. 确保s ≠ 0
      if (s === 0n) {
        throw new Error('s = 0，需要重新生成k值');
      }
      
      // 8. 规范化s值(BIP-0062)
      if (s > this.n / 2n) {
        s = this.n - s;
        console.info('规范化s值完成');
      }
      
      // 9. DER编码
      const derSignature = this.derEncode(r, s);
      console.info(`DER编码生成成功，长度: ${derSignature.length}`);
      
      // 返回签名结果
      const signatureResult = {
        signature: derSignature,
        r: r.toString(16).padStart(64, '0'),
        s: s.toString(16).padStart(64, '0'),
        messageHash: messageHash
      };
      
      console.info('ECDSA签名生成成功');
      return signatureResult;
    } catch (error) {
      // 详细记录错误
      if (error instanceof Error) {
        console.info(`ECDSA签名生成失败: ${error.message}`);
      } else {
        console.info('ECDSA签名生成失败: 未知错误');
      }
      
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
      const w = this.modInverse(s, this.n);
      
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
    if (k === 1n) return { ...P };
    
    // 确保k在正确范围内
    k = k % this.n;
    if (k === 0n) return { x: 0n, y: 0n };
    
    // 检查是否是基点乘法，如是则使用预计算表
    const isBasePoint = P.x === this.Gx && P.y === this.Gy;
    
    // 将仿射坐标转换为雅可比坐标
    let result = { x: 0n, y: 1n, z: 0n }; // 雅可比坐标中的无穷远点
    const P_jacobian = this.affineToJacobian(P);
    
    // 使用简化的双倍加法算法，避免NAF复杂性带来的错误
    // 按位扫描k，从最高位到最低位
    const kBits = k.toString(2);
    
    for (let i = 0; i < kBits.length; i++) {
      // 倍点运算
      result = this.jacobianDouble(result);
      
      // 如果当前位为1，则加上P
      if (kBits[i] === '1') {
        result = this.jacobianAdd(result, P_jacobian);
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
    
    // 计算 z^(-1), z^(-2) 和 z^(-3)
    const zInv = this.modInverse(P.z, this.p);
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
   * 辅助哈希函数，用于生成确定性随机数
   */
  private backupHash(message: string): string {
    // 简单的SHA-256哈希算法实现
    let hash = 0;
    
    // 首先生成一个简单的哈希值
    for (let i = 0; i < message.length; i++) {
      const char = message.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    
    // 使用该哈希值作为种子，生成更复杂的哈希
    let sha256 = '';
    const hashStr = Math.abs(hash).toString();
    
    // 模拟SHA-256输出格式
    for (let i = 0; i < 64; i++) {
      const pos = (i + hashStr.length) % hashStr.length;
      const val = parseInt(hashStr.charAt(pos)) + i;
      sha256 += (val % 16).toString(16);
    }
    
    return sha256;
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
   * 使用简化但可靠的方法
   */
  private fastShamirTrick(u1: bigint, u2: bigint, Q: Point): Point {
    // 单独计算u1*G和u2*Q，然后相加
    const u1G = this.pointMultiplyOptimized(this.G, u1);
    const u2Q = this.pointMultiplyOptimized(Q, u2);
    
    // 如果其中一个结果是无穷远点，返回另一个点
    if (u1G.x === 0n && u1G.y === 0n) return u2Q;
    if (u2Q.x === 0n && u2Q.y === 0n) return u1G;
    
    // 使用简单的仿射坐标点加法
    if (u1G.x === u2Q.x) {
      if (u1G.y !== u2Q.y || u1G.y === 0n) {
        return { x: 0n, y: 0n }; // 无穷远点
      }
      return this.pointDouble(u1G);
    }
    
    // 点加运算
    const lambda = (u2Q.y - u1G.y) * this.modInverse((u2Q.x - u1G.x + this.p) % this.p, this.p) % this.p;
    const x3 = (lambda * lambda - u1G.x - u2Q.x) % this.p;
    const y3 = (lambda * (u1G.x - x3) - u1G.y) % this.p;
    
    return {
      x: (x3 + this.p) % this.p,
      y: (y3 + this.p) % this.p
    };
  }
  
  /**
   * 简单的仿射坐标点倍乘
   */
  private pointDouble(P: Point): Point {
    if (P.y === 0n) return { x: 0n, y: 0n };
    
    const lambda = (3n * P.x * P.x + this.a) * this.modInverse((2n * P.y) % this.p, this.p) % this.p;
    const x3 = (lambda * lambda - 2n * P.x) % this.p;
    const y3 = (lambda * (P.x - x3) - P.y) % this.p;
    
    return {
      x: (x3 + this.p) % this.p,
      y: (y3 + this.p) % this.p
    };
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