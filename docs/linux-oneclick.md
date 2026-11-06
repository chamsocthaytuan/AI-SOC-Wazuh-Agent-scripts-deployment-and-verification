# AI-SOC Linux Agent — OneClick v0.2

**Bản mới:** `scripts/install-oneclick.sh` hiện tự xử lý Wazuh Agent 4.8.2 (nếu chưa có), bắt buộc Suricata, cấu hình Wazuh thu `/var/log/suricata/eve.json` và cài Active Response. Chạy tại **máy Agent** Kali/Ubuntu/Debian, không chạy trên Lab Server.

## Thao tác đề xuất

```bash
cd ~/AI-SOC-Wazuh-Agent-scripts-deployment-and-verification
git fetch origin script-linux && git switch script-linux && git pull --ff-only
bash scripts/install-oneclick.sh --dry-run --manager-ip 10.0.70.12
sudo bash scripts/install-oneclick.sh --apply --manager-ip 10.0.70.12
sudo bash scripts/install-oneclick.sh --verify
```

- **Agent mới:** nhập Agent Name qua prompt (hoặc `--agent-name Ubuntu-Lab-01`) và nhập mật khẩu enrollment **ẩn**. Mật khẩu không đưa vào CLI/log, lưu thành `/var/ossec/etc/authd.pass` với quyền `root:wazuh 0640`. Enrollment dùng TCP 1515; truyền log TCP 1514. Agent mới được pin bản **4.8.2-1** cho Manager lab 4.8.2.
- **Agent đã đăng ký:** giữ nguyên `client.keys`, Agent ID/name và key; không đòi mật khẩu. Nếu Agent vẫn trỏ IP cũ, phải chọn rõ `--repoint-existing --manager-ip 10.0.70.12` trước khi áp dụng. Script sẽ sao lưu file cấu hình.
- **Suricata:** bắt buộc; nếu thiếu thì cài từ APT, cập nhật ruleset, lấy HOME_NET và interface khi lần đầu cài, chạy test `suricata -T`, bật service, kiểm tra `eve.json`. Máy đã có Suricata thì không tự ghi đè YAML.
- **ossec.conf:** chỉ thêm `<localfile>` dạng JSON khi chưa có, backup và kiểm tra XML, restart Agent khi thay đổi.
- **Active Response:** chỉ sao chép scripts Block IP, Isolate và evidence writer; Kill Process mặc định vẫn opt-in/allowlist. Không thực thi firewall hoặc kill process, không bật auto-defense, không thay Manager rule.
- **Giới hạn:** `INSTALL_OK` chứng tỏ cài file/Agent service/EVE/client key; không chứng minh event đã tới Indexer hoặc Verification V2 verdict. Kiểm tra Manager `agent_control -l`, evidence group `ai-soc-linux` và rule 119910 riêng.

**Rollback:** tệp backup `*.bak.aisoc-*` được in ra lúc sửa cấu hình; files AR có bản `.bak-<stamp>` tại thư mục Agent. Không xóa evidence ledger.

---


# AI-SOC Linux Agent — OneClick v0.1

Install from the repository root on an authorized Linux Wazuh Agent (not the Manager). Wazuh Agent and Linux firewall dependencies must already be installed.

## Commands

Preview without making changes:
```bash
bash scripts/install-oneclick.sh --dry-run
```

Install Block IP, Isolate Host and JSONL evidence writer:
```bash
sudo bash scripts/install-oneclick.sh --apply
```

Verify script contents and file ownership/permissions:
```bash
sudo bash scripts/install-oneclick.sh --verify
```

To additionally install the hardened Kill Process implementation at the existing `kill-process0` command name, a pre-existing root-owned nonempty allowlist is required. For a NEW allowlist on an isolated lab, specify one explicitly approved disposable process name:
```bash
sudo bash scripts/install-oneclick.sh --apply --with-kill-process --allow-process aisockill2
```

To verify the optional Kill Process install, add `--with-kill-process` to `--verify`. An existing policy is never overwritten. Do not allowlist privileged system services, the Wazuh agent or management daemons.

## Safety and scope

- Uses the existing `scripts/install.sh` for the actual Agent file installation, including syntax checks, backup, root checks, existing-isolation refusal, Manager TCP 1514 / IP compatibility and dependency checks.
- No firewall rule is installed, no host is isolated, no process is killed and no AR is dispatched during installation.
- The installer does not enable auto-defence, edit Wazuh Agent/Manager configuration, or restart services.
- The current Isolate script is tied to lab Manager IP `192.168.100.192`; review the source before applying to an Agent pointing elsewhere.
- Agent-side file installation is not complete Wazuh / Verification V2 integration. The Manager must separately register commands and provide the `ai-soc-linux` group JSONL localfile configuration to support rule `119910`.
- The hardened Kill Process is not yet fully correlated with the Verification V2 evidence pipeline.
- No claim of live E2E testing on Kali/Ubuntu has been made for this wrapper. Validate with console access, a safe test target and a rollback plan.
