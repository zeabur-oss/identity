<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/cover-zh-TW-dark.avif">
  <img alt="Zeabur Identity：每個人用自己的帳號登入叢集，不必共用管理員檔案。可以用通行密鑰、GitHub、Google 或密碼登入。" src="docs/images/cover-zh-TW-light.avif">
</picture>

<!-- Language names are written in their own script. -->
<!-- vale ZeaburZhTW.Script = NO -->
[English](README.md) · **繁體中文** · [简体中文](README.zh-CN.md)
<!-- vale ZeaburZhTW.Script = YES -->

# Zeabur Identity

**團隊裡每個人用自己的帳號登入 Zeabur 開源版，不必共用管理員密碼或檔案**。Zeabur Identity 是 Zeabur 開源版裡負責確認「誰在登入」的部分：它顯示登入頁，檢查通行密鑰、GitHub 或 Google 帳號、密碼，再依照你給的權限讓每個人進來。

## 使用 Zeabur 開源版？

Zeabur 開源版的登入頁就是 Zeabur Identity，所以執行 Zeabur 開源版的叢集已經裝好了。人員在 Zeabur 開源版裡管理，不在這裡：

- **邀請成員、選擇他們能用的專案**：在**成員**頁操作，見[邀請成員並指派專案權限](https://oss.zeabur.com/zh-TW/docs/zeabur/cluster/members/)。
- **要在叢集上架設 Zeabur 開源版**？Zeabur Identity 要先裝好。[在既有叢集安裝 Zeabur 開源版](https://oss.zeabur.com/zh-TW/docs/zeabur/install/existing-cluster/)列出需要準備的東西，也附上安裝步驟的連結。用一個指令同時裝好 Zeabur 開源版和 Zeabur Identity 的進度，見 [zeabur-oss/zeabur#430](https://github.com/zeabur-oss/zeabur/issues/430)。

要從 Zeabur 搬到自己的伺服器，或想了解 Zeabur 開源版的其他功能，請看 [Zeabur 開源版文件](https://oss.zeabur.com/zh-TW/docs/zeabur/)。

## 它能幫你做什麼

- **每個人有自己的帳號**。不必把同一份管理員檔案複製到每台筆電。有人離開時，結束他的工作階段，10 分鐘內他就無法再存取。
- **用習慣的方式登入**。通行密鑰（Touch ID、Windows Hello 或安全金鑰）、GitHub、Google、公司的登入系統，或密碼。
- **管理員要雙重驗證**。預設情況下，管理員用通行密鑰登入，或用密碼加上驗證器 App 的驗證碼登入。
- **在你的伺服器上執行**。叢集裡只多一個小程式，不需要資料庫，也不依賴外部服務。帳號就存在叢集裡。

## 單獨使用

Zeabur Identity 也可以不搭配 Zeabur 開源版，用在任何自己管理的 Kubernetes 叢集上。

**刪掉 `admin.conf`，用自己的帳號登入叢集。**

大多數自己管理的叢集都靠一份永不過期的管理員 kubeconfig 運作：它被複製到每台筆電，也無法撤銷。Zeabur Identity 用登入取代它：`kubectl` 會開啟瀏覽器，你用通行密鑰、SSO 或密碼登入，拿到的權杖只有幾分鐘效期，不是好幾年。

https://github.com/user-attachments/assets/4c6e29f2-341c-4622-8cc5-4337e13e53b5

*用通行密鑰登入 [Aptakube](https://aptakube.com)：可以瀏覽叢集，但沒有權限的帳號重新啟動 Deployment 時會收到 403。*

### 為什麼選 Zeabur Identity

- **通行密鑰、SSO 或密碼**。Touch ID、Windows Hello 或安全金鑰都能用。同事也可以連結 GitHub 或 Google 帳號，或透過 OpenID 供應商連結公司帳號，或設定至少 15 個字元的密碼。
- **管理員權限只給管理員帳號**。叢集變更用另一個管理員帳號處理。預設用通行密鑰登入，或用密碼加上驗證器 App 的驗證碼；也可以規定只能用通行密鑰。管理員權杖效期 5 分鐘。日常帳號只有你綁定到其群組的權限。
- **不會有永久金鑰留在任何人的筆電上**。權杖只有幾分鐘效期，kube-apiserver 每次請求都會檢查。每個工作階段在登入 12 小時後結束。撤銷某人的工作階段後，他手上的權杖到期就無法再存取，最長 10 分鐘。
- **在它保護的叢集裡執行**。只有一個小 Pod，不需要資料庫，也不需要額外的伺服器。使用者、認證資訊和用戶端都是 Kubernetes 物件。CI 在 k3s 上測試；RKE2 用同一份設定。Argo CD、Grafana 這類 OpenID Connect 應用程式也能用同一個 Issuer。

### 畫面

<table>
  <tr>
    <td width="50%"><picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/images/sign-in-dark.avif">
      <img alt="登入頁，有使用者名稱和密碼、通行密鑰按鈕和「使用 GitHub 繼續」" src="docs/images/sign-in-light.avif">
    </picture></td>
    <td width="50%"><picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/images/setup-dark.avif">
      <img alt="用一次性連結設定登入方式的頁面，可以選「建立通行密鑰」或「使用密碼」" src="docs/images/setup-light.avif">
    </picture></td>
  </tr>
  <tr>
    <td align="center"><b>日常登入</b><br>通行密鑰或 GitHub</td>
    <td align="center"><b>加入</b><br>一次性邀請連結</td>
  </tr>
</table>

### 運作方式

1. 你執行 `kubectl get pods`，瀏覽器開啟 Zeabur Identity 的登入頁。
2. 你登入後，`kubectl` 拿到 10 分鐘內有效的權杖，並在你工作時自動更新。
3. Kubernetes 自己檢查權杖，你的請求不會經過 Zeabur Identity。

要變更叢集時，用管理員帳號登入。登入後馬上就有完整權限，不必再登入一次。要用更嚴格的規則，例如管理員只能用安全金鑰，見[管理員帳號與工作階段](docs/zh-TW/users/admin-sessions.mdx)。

### 開始使用

跟著[逐步教學](docs/zh-TW/get-started/quickstart.mdx)在 Ubuntu 伺服器上安裝 k3s、下載並驗證 Zeabur Identity，再從你的電腦（macOS、Linux 或 Windows）登入。

既有叢集要先[下載並驗證 Zeabur Identity](docs/zh-TW/reference/releases.mdx)，再用叢集管理員的 kubeconfig 安裝：

```sh
export ZEABUR_IDENTITY_ISSUER=https://login.example.com
zeabur-identityctl crds | kubectl apply --server-side -f -
zeabur-identityctl manifests --image "$ZEABUR_IDENTITY_IMAGE" --serve-arg=--invitations | kubectl apply --server-side -f -
kubectl -n zeabur-identity rollout status deploy/zeabur-identity --timeout=180s
# 印出 kube-apiserver 的設定，以及在你的發行版上安裝的方式：
zeabur-identityctl kube-config --distro k3s > authn.yaml
# 一次性連結：打開後設定第一位管理員的登入方式。
zeabur-identityctl setup-link --username admin
```

[安裝到既有叢集](docs/zh-TW/get-started/existing-cluster.mdx)列出每個步驟，每步都有確認結果的指令。開發版建置方式見[從原始碼建置](CONTRIBUTING.md#building-from-source)。

接下來：

- 用 [GitHub、Google 或你自己的 OpenID 供應商](docs/zh-TW/users/upstream-sign-in.mdx)（例如 Keycloak）登入。
- 用 `zeabur-identityctl client create` [註冊用戶端](docs/zh-TW/users/clients.mdx)，例如 Grafana 或 Argo CD。
- [管理使用者](docs/zh-TW/users/manage-users.mdx)：群組、管理員權限、遺失通行密鑰、移除成員；也可以寫一個小腳本[從目錄同步使用者](docs/zh-TW/users/provisioning.mdx)。
- 用 `zeabur-identityctl invite --username alice` 傳一次性連結給別人。伺服器要像上面一樣加上 `--invitations` 啟動，否則連結無法使用。

## 文件

給 Zeabur 開源版使用者：

- [邀請成員並指派專案權限](https://oss.zeabur.com/zh-TW/docs/zeabur/cluster/members/)
- [在既有叢集安裝 Zeabur 開源版](https://oss.zeabur.com/zh-TW/docs/zeabur/install/existing-cluster/)

單獨使用 Zeabur Identity：

- [在 Ubuntu 的 k3s 上安裝](docs/zh-TW/get-started/quickstart.mdx)和[安裝到既有叢集](docs/zh-TW/get-started/existing-cluster.mdx)
- [新增與管理使用者](docs/zh-TW/users/manage-users.mdx)、[管理員帳號與工作階段](docs/zh-TW/users/admin-sessions.mdx)、[登出、救援與移除使用者](docs/zh-TW/users/offboarding.mdx)、[用外部帳號登入](docs/zh-TW/users/upstream-sign-in.mdx)、[從目錄同步使用者](docs/zh-TW/users/provisioning.mdx)和[註冊用戶端](docs/zh-TW/users/clients.mdx)
- [保留不經過 Zeabur Identity 的入口](docs/zh-TW/operations/emergency-access.mdx)、[備份與還原](docs/zh-TW/operations/backup-restore.mdx)和[升級與回復](docs/zh-TW/operations/upgrade.mdx)
- [架構](docs/zh-TW/reference/architecture.mdx)：各部分如何搭配、安全性質、各個 crate。
- [規格符合度](docs/zh-TW/reference/conformance.mdx)：每一條規格要求對應到的程式碼和測試。
- [發行檔與驗證](docs/zh-TW/reference/releases.mdx)：支援的平台、標籤流程、簽章、總和檢查碼和 SBOM。

## 參與貢獻

見 [CONTRIBUTING.md](CONTRIBUTING.md)：開發環境、CI 執行的檢查和相依套件政策。安全性問題請依照 [SECURITY.md](SECURITY.md) 回報。

## 授權與致謝

Apache-2.0。貢獻依 [Developer Certificate of Origin](DCO) 接受。

登入頁的樣式和元件類別來自 Zeabur 開源版的設計系統（Apache-2.0，以 [shadcn/ui](https://ui.shadcn.com) 為基礎，MIT），並附帶 [Geist](https://github.com/vercel/geist-font) 字型（SIL Open Font License 1.1，見設計系統裡的 `vendor/geist/LICENSE.txt`）。容器映像檔包含 nixpkgs 打包的 Mozilla CA 憑證套件（MPL-2.0）。
