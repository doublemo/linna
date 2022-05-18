# typescript 模块
实现Linna的js模块方法

### 创建项目

```sh
mkdir -p ts-project/{src,build}
cd ts-project
```

### 使用npm初始化项目

这里面要下载typescript

```sh
npm init -y
npm install --save-dev typescript
```

### 初始化typescript

```sh
npx tsc --init
```

### 配置typescript
```json
{
  "files": [
    "./src/main.ts"
  ],
  "compilerOptions": {
    "target": "es5",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "outFile": "./build/index.js",
    "typeRoots": [
      "./node_modules"
    ]
  }
}
```

### 下载Linna typescript 接口文件


```sh
npm i 'https://github.com/heroiclabs/nakama-common'
```

### 目录结构

```sh
.
├── build
├── node_modules
│   ├── nakama-runtime
│   └── typescript
├── package-lock.json
├── package.json
├── src
└── tsconfig.json
```

### 编写测试代码

在src目录中新建main.ts, 输入 代码

```ts
let InitModule: naruntime.InitModule =
        function(ctx: naruntime.Context, logger: naruntime.Logger, nk: naruntime.Linna, initializer: naruntime.Initializer) {
    logger.info("Hello World!   -- js");
} 
```

### 编译
```sh
npx tsc
```

生成完后，将build目录的index.js复制到linna的模块加载目录中，完成