<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/cover-zh-CN-dark.avif">
  <img alt="Zeabur Identity：每个人用自己的账号登录集群，不必共用管理员文件。可以用通行密钥、GitHub、Google 或密码登录。" src="docs/images/cover-zh-CN-light.avif">
</picture>

<!-- Language names are written in their own script. -->
<!-- vale ZeaburZhCN.Script = NO -->
[English](README.md) · [繁體中文](README.zh-TW.md) · **简体中文**
<!-- vale ZeaburZhCN.Script = YES -->

# Zeabur Identity

**团队里每个人用自己的账号登录 Zeabur 开源版，不必共用管理员密码或文件**。Zeabur Identity 是 Zeabur 开源版里负责确认“谁在登录”的部分：它显示登录页，检查通行密钥、GitHub 或 Google 账号、密码，再按照你给的权限让每个人进来。

## 使用 Zeabur 开源版？

Zeabur 开源版的登录页就是 Zeabur Identity，所以运行 Zeabur 开源版的集群已经装好了。人员在 Zeabur 开源版里管理，不在这里：

- **邀请成员、选择他们能用的项目**：在**成员**页操作，见[邀请成员并分配项目权限](https://oss.zeabur.com/zh-CN/docs/zeabur/cluster/members/)。
- **要在集群上部署 Zeabur 开源版**？需要先装好 Zeabur Identity。[在已有集群上安装 Zeabur 开源版](https://oss.zeabur.com/zh-CN/docs/zeabur/install/existing-cluster/)列出了需要准备的东西，也附有安装步骤的链接。用一条命令同时装好 Zeabur 开源版和 Zeabur Identity 的进度，见 [zeabur-oss/zeabur#430](https://github.com/zeabur-oss/zeabur/issues/430)。

要从 Zeabur 迁移到自己的服务器，或想了解 Zeabur 开源版的其他功能，请看 [Zeabur 开源版文档](https://oss.zeabur.com/zh-CN/docs/zeabur/)。

## 它能帮你做什么

- **每个人有自己的账号**。不必把同一份管理员文件复制到每台笔记本。有人离开时，结束他的会话，10 分钟内他就无法再访问。
- **用习惯的方式登录**。通行密钥（Touch ID、Windows Hello 或安全密钥）、GitHub、Google、公司的登录系统，或密码。
- **管理员要双重验证**。默认情况下，管理员用通行密钥登录，或用密码加上验证器 App 的验证码登录。
- **在你的服务器上运行**。集群里只多运行一个程序，不需要数据库，也不依赖外部服务。账号就存在集群里。

## 单独使用

Zeabur Identity 也可以不搭配 Zeabur 开源版，用在任何自己管理的 Kubernetes 集群上。

**删掉 `admin.conf`，用自己的账号登录集群。**

大多数自己管理的集群都靠一份永不过期的管理员 kubeconfig 运作：它被复制到每台笔记本，也无法吊销。Zeabur Identity 用登录取代它：`kubectl` 会打开浏览器，你用通行密钥、SSO 或密码登录，拿到的令牌只有几分钟有效期，而不是好几年。

https://github.com/user-attachments/assets/4c6e29f2-341c-4622-8cc5-4337e13e53b5

*用通行密钥登录 [Aptakube](https://aptakube.com)：可以浏览集群，但没有权限的账号重启 Deployment 时会收到 403。*

### 为什么选 Zeabur Identity

- **通行密钥、SSO 或密码**。Touch ID、Windows Hello 或安全密钥都能用。同事也可以关联 GitHub 或 Google 账号，或通过 OpenID 提供方关联公司账号，或设置至少 15 个字符的密码。
- **管理员权限只给管理员账号**。集群变更用另一个管理员账号处理。默认用通行密钥登录，或用密码加上验证器 App 的验证码；也可以规定只能用通行密钥。管理员令牌有效期 5 分钟。日常账号只有你绑定到其用户组的权限。
- **不会有永久密钥留在任何人的笔记本上**。令牌只有几分钟有效期，kube-apiserver 每次请求都会检查。每个会话在登录 12 小时后结束。吊销某人的会话后，他手上的令牌到期就无法再访问，最长 10 分钟。
- **在它保护的集群里运行**。只有一个小 Pod，不需要数据库，也不需要额外的服务器。用户、凭据和客户端都是 Kubernetes 对象。CI 在 k3s 上测试；RKE2 用同一份配置。Argo CD、Grafana 这类 OpenID Connect 应用也能用同一个 Issuer。

### 界面

<table>
  <tr>
    <td width="50%"><picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/images/sign-in-dark.avif">
      <img alt="登录页，有用户名和密码、通行密钥按钮和“使用 GitHub 继续”" src="docs/images/sign-in-light.avif">
    </picture></td>
    <td width="50%"><picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/images/setup-dark.avif">
      <img alt="用一次性链接设置登录方式的页面，可以选“创建通行密钥”或“使用密码”" src="docs/images/setup-light.avif">
    </picture></td>
  </tr>
  <tr>
    <td align="center"><b>日常登录</b><br>通行密钥或 GitHub</td>
    <td align="center"><b>加入</b><br>一次性邀请链接</td>
  </tr>
</table>

### 工作方式

1. 你运行 `kubectl get pods`，浏览器打开 Zeabur Identity 的登录页。
2. 你登录后，`kubectl` 拿到 10 分钟内有效的令牌，并在你工作时自动续期。
3. Kubernetes 自己检查令牌，你的请求不会经过 Zeabur Identity。

要变更集群时，用管理员账号登录。登录后马上就有完整权限，不必再登录一次。要用更严格的规则，例如管理员只能用安全密钥，见[管理员账号与会话](docs/zh-CN/users/admin-sessions.mdx)。

### 开始使用

跟着[分步教程](docs/zh-CN/get-started/quickstart.mdx)在 Ubuntu 服务器上安装 k3s、下载并验证 Zeabur Identity，再从你的电脑（macOS、Linux 或 Windows）登录。

已有集群要先[下载并验证 Zeabur Identity](docs/zh-CN/reference/releases.mdx)，再用集群管理员的 kubeconfig 安装：

```sh
export ZEABUR_IDENTITY_ISSUER=https://login.example.com
zeabur-identityctl crds | kubectl apply --server-side -f -
zeabur-identityctl manifests --image "$ZEABUR_IDENTITY_IMAGE" --serve-arg=--invitations | kubectl apply --server-side -f -
kubectl -n zeabur-identity rollout status deploy/zeabur-identity --timeout=180s
# 打印 kube-apiserver 的配置，以及在你的发行版上安装的方法：
zeabur-identityctl kube-config --distro k3s > authn.yaml
# 一次性链接：打开后设置第一位管理员的登录方式。
zeabur-identityctl setup-link --username admin
```

[安装到已有集群](docs/zh-CN/get-started/existing-cluster.mdx)列出了每个步骤，每步都有确认结果的命令。开发版的构建方法见[从源代码构建](CONTRIBUTING.md#building-from-source)。

接下来：

- 用 [GitHub、Google 或你自己的 OpenID 提供方](docs/zh-CN/users/upstream-sign-in.mdx)（例如 Keycloak）登录。
- 用 `zeabur-identityctl client create` [注册客户端](docs/zh-CN/users/clients.mdx)，例如 Grafana 或 Argo CD。
- [管理用户](docs/zh-CN/users/manage-users.mdx)：用户组、管理员权限、丢失通行密钥、移除成员；也可以写一个小脚本[从目录同步用户](docs/zh-CN/users/provisioning.mdx)。
- 用 `zeabur-identityctl invite --username alice` 给别人发一次性链接。服务器要像上面一样加上 `--invitations` 启动，否则链接无法使用。

## 文档

给 Zeabur 开源版用户：

- [邀请成员并分配项目权限](https://oss.zeabur.com/zh-CN/docs/zeabur/cluster/members/)
- [在已有集群上安装 Zeabur 开源版](https://oss.zeabur.com/zh-CN/docs/zeabur/install/existing-cluster/)

单独使用 Zeabur Identity：

- [在 Ubuntu 的 k3s 上安装](docs/zh-CN/get-started/quickstart.mdx)和[安装到已有集群](docs/zh-CN/get-started/existing-cluster.mdx)
- [添加与管理用户](docs/zh-CN/users/manage-users.mdx)、[管理员账号与会话](docs/zh-CN/users/admin-sessions.mdx)、[退出登录、找回账号与移除用户](docs/zh-CN/users/offboarding.mdx)、[用外部账号登录](docs/zh-CN/users/upstream-sign-in.mdx)、[从目录同步用户](docs/zh-CN/users/provisioning.mdx)和[注册客户端](docs/zh-CN/users/clients.mdx)
- [保留不经过 Zeabur Identity 的入口](docs/zh-CN/operations/emergency-access.mdx)、[备份与恢复](docs/zh-CN/operations/backup-restore.mdx)和[升级与回滚](docs/zh-CN/operations/upgrade.mdx)
- [架构](docs/zh-CN/reference/architecture.mdx)：各部分如何配合、安全特性、各个 crate。
- [规范符合度](docs/zh-CN/reference/conformance.mdx)：每一条规范要求对应的代码和测试。
- [发行文件与验证](docs/zh-CN/reference/releases.mdx)：支持的平台、标签流程、签名、校验和与 SBOM。

## 参与贡献

见 [CONTRIBUTING.md](CONTRIBUTING.md)：开发环境、CI 运行的检查和依赖政策。安全问题请按照 [SECURITY.md](SECURITY.md) 报告。

## 许可与致谢

Apache-2.0。贡献按 [Developer Certificate of Origin](DCO) 接受。

登录页的样式和组件类名来自 Zeabur 开源版的设计系统（Apache-2.0，基于 [shadcn/ui](https://ui.shadcn.com)，MIT），并附带 [Geist](https://github.com/vercel/geist-font) 字体（SIL Open Font License 1.1，见设计系统中的 `vendor/geist/LICENSE.txt`）。容器镜像包含 nixpkgs 打包的 Mozilla CA 证书包（MPL-2.0）。
