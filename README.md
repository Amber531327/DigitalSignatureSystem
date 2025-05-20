# 数字签名可视化系统

这是一个交互式的数字签名算法可视化系统，支持 RSA、DSA 和 ECDSA 三种签名算法，通过动画展示数字签名的工作原理。系统采用自实现的加密算法，所有算法都使用纯JavaScript/TypeScript实现，不依赖于外部加密库，便于教学和理解。

## 功能特点

- **多算法支持**：实现了RSA（含PSS填充）、DSA和ECDSA三种经典数字签名算法
- **完整生命周期**：可视化展示数字签名的完整生命周期，包括密钥生成、签名创建和签名验证
- **交互式体验**：提供直观的用户界面，可以输入任意消息并观察签名过程
- **安全验证**：内置篡改检测功能，展示数字签名如何防止消息被篡改
- **动画效果**：生动的动画展示各算法内部工作原理和数据流转过程
- **教学价值**：每个步骤都有详细的解释，适合密码学教学和学习

## 算法实现

### RSA签名算法
- 支持2048位密钥
- 实现PSS填充机制提高安全性
- 包含密钥生成、签名、验证的完整流程
- 支持各种消息长度的签名和验证

### DSA签名算法
- 标准实现，支持1024位素数模数和160位素数阶
- 使用确定性k值生成，避免随机数问题
- 完整的密钥生成、签名和验证流程

### ECDSA签名算法
- 基于secp256k1椭圆曲线（与比特币和以太坊相同的曲线）
- 实现了椭圆曲线上的点加法、点倍乘等基本运算
- 支持DER编码的签名格式
- 使用RFC 6979确定性k值，防止随机数弱点

## 安装

首先，确保你的系统已安装 Node.js (14.x 或更高版本)。

1. 克隆项目到本地：

```bash
git clone <仓库地址>
cd 数字签名可视化系统
```

2. 安装依赖：

```bash
npm install
# 或者使用yarn
yarn install
```

## 运行

开发模式运行：

```bash
npm run dev
# 或者使用yarn
yarn dev
```

然后在浏览器中访问 `http://localhost:3000` 即可查看项目。

运行测试：

```bash
npm test
# 或者测试特定算法
npm test -- --testPathPattern=RSA
```

## 使用方法

1. 在首页选择一种签名算法（RSA、DSA 或 ECDSA）
2. 按照界面提示，依次完成：
   - 输入要签名的消息
   - 生成密钥对（可观察公钥和私钥的结构）
   - 使用私钥生成签名（可观察签名生成的中间步骤）
   - 使用公钥验证签名（可尝试修改消息或签名观察验证结果）
3. 在右侧可视化区域观察每一步的过程和结果，帮助理解算法原理

## 项目结构

```
/
├── algorithms/           # 签名算法实现
│   ├── RSA.ts            # RSA签名算法实现
│   ├── DSA.ts            # DSA签名算法实现
│   ├── ECDSA.ts          # ECDSA椭圆曲线签名算法实现
│   ├── types.ts          # 类型定义
│   ├── index.ts          # 算法工厂和导出
│   └── __tests__/        # 算法单元测试
│       ├── RSA.test.ts   # RSA算法测试
│       ├── DSA.test.ts   # DSA算法测试
│       └── ECDSA.test.ts # ECDSA算法测试
├── components/           # 前端组件
│   ├── AlgorithmSelector.tsx  # 算法选择组件
│   ├── StepActions.tsx        # 步骤操作组件
│   ├── UserRole.tsx           # 用户角色展示组件
│   ├── VisualizationArea.tsx  # 可视化展示区域组件
│   ├── ParticleBackground.tsx # 背景粒子效果组件
│   ├── SuccessConfetti.tsx    # 成功验证庆祝效果
│   ├── TypingText.tsx         # 打字效果文本组件
│   ├── ThemeIcons.tsx         # 主题图标组件
│   └── VerificationBadge.tsx  # 验证结果标识组件
├── pages/                # 页面目录
│   ├── _app.tsx          # Next.js 应用入口
│   └── index.tsx         # 主页面实现
├── styles/               # 样式文件
│   └── globals.css       # 全局样式
└── public/               # 静态资源
```

## 技术栈

- **前端框架**：React/Next.js
- **语言**：TypeScript
- **动画库**：Framer Motion
- **测试工具**：Jest
- **样式**：CSS/Tailwind CSS

## 开发和贡献

欢迎贡献代码或提出建议！请遵循以下步骤：

1. Fork本仓库
2. 创建你的特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交你的更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建一个Pull Request

## 许可证

MIT许可证 - 详见 LICENSE 文件 