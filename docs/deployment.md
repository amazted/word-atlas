# 部署 / Deployment

`npm run build` 生成纯静态站点 `dist/`，可以放到任何静态托管（Nginx、Cloudflare Pages、Vercel、GitHub Pages）。

## 子路径

```bash
ATLAS_BASE=/words/ npm run build
```

## Nginx 示例

```nginx
location ^~ /words/ {
    alias /var/www/word-atlas/;
    try_files $uri $uri/ /words/index.html;
    expires 7d;
}
```

## GitHub Pages

仓库带有 `.github/workflows/pages.yml`。在仓库 Settings → Pages 选择 “GitHub Actions”，然后手动运行 “Deploy to GitHub Pages”。

## Vercel 密码保护

1. 在 Vercel 项目的 Environment Variables 中添加 `PASSWORD`，Production 和 Preview 环境都要设置。
2. 重新部署（修改环境变量不会自动应用到已有部署）。
3. 根目录的 `middleware.ts` 会拦截所有请求：未验证时返回密码页，密码正确后写入 `HttpOnly` Cookie（30 天有效）。不设置 `PASSWORD` 时不启用保护。

本地 `npm run dev` / `npm run preview` 由 `vite.config.ts` 中的插件提供同样的保护。纯静态托管（如 GitHub Pages、对象存储）不会执行 `middleware.ts`，密码保护不生效，需要平台自带的访问控制。

## 体积

插画与音频合计约数百 MB。建议在 CDN 后部署，或按需只发布 `thumb/` 和部分音频。
