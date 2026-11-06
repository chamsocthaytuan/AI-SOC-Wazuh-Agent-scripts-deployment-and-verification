# AI-SOC — Hướng dẫn cài Linux Agent từ đầu: Wazuh 4.x + Suricata + OneClick Active Response

**Môi trường:** LAB AI-SOC, Ubuntu/Debian/Kali Linux dùng systemd và apt. **Phiên bản tài liệu:** 2026-11-06. **Không tự chạy lệnh cô lập/chặn IP/kill process trên máy ngoài lab.**

> **Lưu ý:** Wazuh Agent và Suricata là hai thành phần độc lập. Wazuh Agent phục vụ log collection và Active Response; Suricata là network IDS. Wazuh đọc file EVE JSON của Suricata. Rule **119910 dành cho JSONL evidence Active Response, không phải rule Suricata**.

## 0. Mô hình và nguyên tắc

| Nơi chạy | Vai trò | Ví dụ |
| --- | --- | --- |
| AI-SOC Ubuntu Server | Docker Wazuh Manager, Indexer, Orchestrator, Command Center | `192.168.100.192` |
| Máy Linux Agent mới | Cài Wazuh Agent + Suricata (nếu cần) + OneClick Active Response | Kali/Ubuntu, địa chỉ riêng trong LAN |
| Repo Agent | [script-linux](https://github.com/chamsocthaytuan/AI-SOC-Wazuh-Agent-scripts-deployment-and-verification/tree/script-linux) | Script và installer |
| Repo AI-SOC server | [ai_soc](https://github.com/chamsocthaytuan/ai_soc/tree/develop) | Manager-side group/rule và Verification V2 |

- **Tuyệt đối không cài lại Agent** nếu máy đã có Agent đăng ký, ví dụ Kali Agent 008; trước hết kiểm tra rồi nâng cấp/cấu hình theo nhánh riêng.
- Các lệnh dành cho máy mới không chạy trên Manager; các lệnh `docker exec wazuh-manager` chỉ chạy trên server.
- Nếu Agent còn chưa giao tiếp được với Manager, **không** cài/kích hoạt script cô lập. Manager IP trong `isolate.sh` bản lab hiện ghim theo `192.168.100.192`, TCP 1514.
- Giữ console/snapshot VM để khôi phục khi test firewall. OneClick **chỉ chép file**, không tự thực hiện Active Response.
- Wazuh Manager 4.x: Agent cần kết nối TCP 1514 và enroll TCP 1515; 55000 là API của Manager, không cần mở cho Agent ở đường enroll thông thường.

## 1. Kiểm tra AI-SOC Server trước khi cài (chạy trên Ubuntu Server)

~~~bash
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | grep -E 'NAMES|wazuh-manager'
docker exec wazuh-manager /var/ossec/bin/wazuh-control info -v
docker port wazuh-manager | grep -E '1514|1515'
~~~

**Điều kiện đạt:** Container Manager đang chạy, có port 1514/TCP và 1515/TCP được xuất ra địa chỉ Linux Agent có thể truy cập. Ghi lại version của Manager. Nếu Manager báo **v4.8.2**, khuyến nghị Agent cũng là **4.8.2**, không vô tình cài bản 4.x mới hơn hoặc 5.x. Nếu Manager đang dùng version khác, chọn Agent tương thích (không mới hơn Manager).

Cũng có thể xác nhận rule evidence đã khai báo:

~~~bash
docker exec wazuh-manager grep -Rn '119910' /var/ossec/etc/rules/
docker exec wazuh-manager /var/ossec/bin/wazuh-analysisd -t && echo MANAGER_CONFIG_OK
~~~

Nếu 1515/TCP chưa được publish hoặc không có authd, dừng để sửa enrollment của Manager trước. Không làm bước Agent dựa trên một Manager không truy cập được.

## 2. Kiểm tra Linux Agent mới (chạy trên Kali/Ubuntu)

~~~bash
cat /etc/os-release | head -n 5
ip -br addr
dpkg-query -W wazuh-agent suricata 2>/dev/null || true
~~~

Nếu đã có `wazuh-agent` hoặc `/var/ossec/etc/client.keys`, **dừng nhánh cài mới** để tránh mất identity Agent trước đó.

~~~bash
sudo apt-get update
sudo apt-get install -y curl ca-certificates gnupg git jq netcat-openbsd python3 iproute2 iptables nftables util-linux
nc -vz -w 3 192.168.100.192 1514 1515
~~~

Kết nối hai cổng phải thành công; nếu lỗi, kiểm tra firewall Manager, mạng VM (NAT/bridged), routing và Docker port mapping. Không tắt firewall đại trà để sửa lỗi.

## 3. Cài Wazuh Agent tương thích Wazuh Manager

Lệnh này dành cho **APT trên Ubuntu/Debian/Kali**, dùng repository Wazuh 4.x.

~~~bash
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo chmod 0644 /usr/share/keyrings/wazuh.gpg && sudo apt-get update
~~~

Xem version nào có trong repository:

~~~bash
apt-cache madison wazuh-agent | head -n 15
~~~

**Nếu Manager là Wazuh 4.8.2** và danh sách có `4.8.2-1`, chạy (đặt tên Agent duy nhất, không dùng lại ID/name của Agent cũ):

~~~bash
sudo env WAZUH_MANAGER='192.168.100.192' WAZUH_AGENT_NAME='linux-lab-new' apt-get install -y wazuh-agent=4.8.2-1
sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent
sudo apt-mark hold wazuh-agent
~~~

Nếu `4.8.2-1` không có, **không tự thay bằng version mới nhất**: dừng và dùng package đúng version Manager hoặc tương thích đã được duyệt. Với Manager khác 4.8.2, đổi package pin sau khi xác nhận version. Dùng `apt-mark hold` để tránh upgrade Agent vượt Manager.

Kiểm tra kết nối:

~~~bash
sudo systemctl --no-pager --full status wazuh-agent
sudo tail -n 30 /var/ossec/logs/ossec.log
sudo ss -tnp | grep '192.168.100.192:1514' || true
~~~

Trên **Ubuntu Server** (một terminal khác):

~~~bash
docker exec wazuh-manager /var/ossec/bin/agent_control -l
~~~

Tìm đúng Agent `linux-lab-new`, ghi **ID thực tế** do Manager cấp. Không giả định ID = 008.

## 4. Cài Suricata trên Linux Agent (nếu chưa có network IDS)

> Suricata **không cần cài trên mỗi Agent** nếu bạn đã có sensor tập trung nhìn thấy traffic cần giám sát. Cách dưới đây cài Suricata chạy **ngay trên Linux Agent** để quan sát traffic mà giao diện mạng của Agent nhìn thấy. Suricata trong Docker ở AI-SOC Server là sensor **khác**, không mặc nhiên nhìn được traffic của các máy VM khác nếu không có mirror/SPAN/TAP/routing phù hợp.

~~~bash
sudo apt-get install -y suricata suricata-update
suricata -V
ip -br addr
~~~

1. Ghi tên interface có traffic cần giám sát (ví dụ `eth0`, `ens33`, `enp0s3`), không đoán.
2. Sao lưu rồi mở file cấu hình:

~~~bash
sudo cp -a /etc/suricata/suricata.yaml "/etc/suricata/suricata.yaml.bak.$(date +%Y%m%d%H%M%S)"
sudo nano /etc/suricata/suricata.yaml
~~~

Tại **các mục đã có sẵn** (không thêm block trùng lặp), chỉnh:

~~~yaml
vars:
  address-groups:
    HOME_NET: "[192.168.100.0/24]"

af-packet:
  - interface: enp0s3  # THAY bằng tên interface THẬT ở bước trên
~~~

Trong mục `outputs`, bảo đảm `eve-log` được bật với `filename: eve.json` và các event types cần thiết (thường gồm `alert`, `flow`, `dns`, `http`). **Giữ các cấu hình mặc định khác**, không thay cả `suricata.yaml` bằng snippet trên.

~~~bash
sudo suricata-update
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo systemctl enable --now suricata
~~~

**Chỉ khởi động sau khi `suricata -T` thành công.** Kiểm tra:

~~~bash
sudo systemctl --no-pager --full status suricata
sudo ls -lh /var/log/suricata/eve.json
sudo tail -n 3 /var/log/suricata/eve.json | jq -c '{event_type,src_ip,dest_ip}'
~~~

Chưa thấy `event_type=alert` chưa có nghĩa cài Suricata sai; cần có lưu lượng thực tế khớp một IDS rule. Khi chạy trong VirtualBox/VM, sensor chỉ thấy những gói mạng được giao diện VM cung cấp.

## 5. Cho Wazuh Agent đọc log Suricata (trên Linux Agent)

Sao lưu cấu hình Wazuh Agent và chỉnh file:

~~~bash
sudo cp -a /var/ossec/etc/ossec.conf "/var/ossec/etc/ossec.conf.bak.$(date +%Y%m%d%H%M%S)"
sudo nano /var/ossec/etc/ossec.conf
~~~

**Chèn đoạn này vào bên trong một block `<ossec_config> ... </ossec_config>` đã có**, không xóa cấu hình `<client>` hay tạo file mới thay thế:

~~~xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
~~~

Áp dụng:

~~~bash
sudo systemctl restart wazuh-agent
sudo systemctl is-active wazuh-agent
sudo tail -n 25 /var/ossec/logs/ossec.log
~~~

**Hai luồng log độc lập:**
- `/var/log/suricata/eve.json` → Suricata events → Wazuh decoder/rules cho Suricata.
- `/var/ossec/logs/ai-soc-verification.json` → Active Response evidence → rule **119910** → Verification Worker.

Không dùng rule 119910 để kết luận Suricata đang hoạt động.

## 6. Cài AI-SOC Linux Active Response OneClick (trên Linux Agent)

~~~bash
git clone --branch script-linux --depth 1 https://github.com/chamsocthaytuan/AI-SOC-Wazuh-Agent-scripts-deployment-and-verification.git
cd AI-SOC-Wazuh-Agent-scripts-deployment-and-verification
bash scripts/install-oneclick.sh --dry-run
~~~

Sau khi preview báo ổn, cài:

~~~bash
sudo bash scripts/install-oneclick.sh --apply
sudo bash scripts/install-oneclick.sh --verify
~~~

Bộ mặc định cài `block-ip.py`, `isolate.sh`, `ai_soc_evidence.py`. Installer kiểm tra cú pháp, dependencies, identity Manager IP/protocol, active isolation, file permissions; tạo backup khi thay script; không chạy chặn IP/cô lập và không sửa Manager.

**Kill Process cố ý không tự bật**, vì cần policy allowlist. Để cài bản hardened *chỉ trên lab* và cho phép process mẫu đã duyệt:

~~~bash
sudo bash scripts/install-oneclick.sh --apply --with-kill-process --allow-process aisockill2
sudo bash scripts/install-oneclick.sh --verify --with-kill-process
~~~

Nếu đã có `kill-process-policy.json`, lệnh tạo policy mới sẽ từ chối ghi đè; dùng policy hiện tại nếu đã duyệt. Không cho phép process hệ thống, Wazuh, sshd hay database.

## 7. Đồng bộ cấu hình evidence từ AI-SOC Server xuống Agent

**Chạy trên Ubuntu AI-SOC Server**, trong checkout chính `chamsocthaytuan/ai_soc` có script `scripts/deploy-wazuh-evidence-config.sh`. Không chạy lệnh này từ repo Agent và không chạy trong Kali.

~~~bash
cd ~/ai_soc
test -f scripts/deploy-wazuh-evidence-config.sh && echo SCRIPT_FOUND
docker exec wazuh-manager /var/ossec/bin/agent_control -l
~~~

Thay `NNN` bằng **Agent ID thực** mới cấp (ví dụ `009`, không mặc định 008):

~~~bash
bash scripts/deploy-wazuh-evidence-config.sh NNN
docker exec wazuh-manager /var/ossec/bin/agent_groups -S -i NNN
~~~

Script chính của AI-SOC kiểm tra rule 119910 với `wazuh-logtest`, tạo group `ai-soc-linux`, publish `agent.conf` chuyên đọc `ai-soc-verification.json` và gán Agent vào group **không xóa group trước đó**. Nếu file group đã tồn tại với nội dung khác, script dừng thay vì ghi đè. Không tự restart Manager.

> **Quan trọng:** Cài script lên endpoint + đồng bộ evidence group **chưa đồng nghĩa Orchestrator đã được đăng ký đầy đủ các custom commands trong Manager**. Kiểm tra Manager runtime có command của `block-ip.py`, `isolate.sh` và (nếu dùng) `kill-process0` theo thiết kế của nhánh đang triển khai. Không tạo tự động block/isolate chỉ dựa trên mọi alert Suricata.

## 8. Kiểm tra bàn giao — không kích hoạt phòng thủ thật

**Linux Agent:**

~~~bash
sudo systemctl is-active wazuh-agent suricata
sudo bash scripts/install-oneclick.sh --verify
sudo ls -l /var/ossec/logs/ai-soc-verification.json /var/log/suricata/eve.json
~~~

**Ubuntu AI-SOC Server:**

~~~bash
docker exec wazuh-manager /var/ossec/bin/agent_control -i NNN
docker exec wazuh-manager /var/ossec/bin/agent_groups -S -i NNN
docker exec wazuh-manager /var/ossec/bin/wazuh-analysisd -t && echo RULE_CONFIG_OK
~~~

Đạt phần cài đặt khi Agent `Active`, Suricata chạy và có EVE JSON, OneClick trả `VERIFY_OK`, group config đã sync, rule 119910 được Manager nhận. **Chưa cần có alert 119910** nếu chưa có lần thực thi Active Response tạo evidence hợp lệ.

Phần Verification V2 E2E còn phải được test riêng với một **execution_id đã commit trong PostgreSQL**:
`Orchestrator → Manager → Agent → EXECUTION_COMPLETED + independent STATE_SNAPSHOT → rule119910 → Indexer → evidence_ledger → verdict`.
Không giả lập execution ID để gọi là E2E thành công; không dựa vào Manager ACK để đánh dấu `VERIFIED`.

## 9. Lỗi thường gặp

| Hiện tượng | Kiểm tra chính |
|---|---|
| Không enroll được Agent | TCP 1515, authd Manager, agent name trùng, Manager version/agent version |
| Agent disconnected | TCP 1514, NAT/bridged, firewall, log `/var/ossec/logs/ossec.log` |
| `apt install wazuh-agent` đòi bản mới hơn Manager | Phải pin đúng version tương thích, không dùng latest |
| Suricata service không chạy | Sai tên interface trong `af-packet`, `suricata -T`, journalctl |
| EVE không có alert | Chưa có traffic khớp IDS rule; kiểm tra ruleset và traffic visibility |
| OneClick từ chối cài | Agent thiếu, Manager IP khác 192.168.100.192, thiếu tools, có isolation đang active |
| Không thấy rule 119910 trong alerts | Chưa có JSONL evidence hợp lệ hoặc group chưa sync; chỉ có Suricata EVE không tạo rule này |
| `UNVERIFIED` trên Center | Chưa đủ execution/state evidence hoặc Orchestrator đang dry-run; không đồng nghĩa Agent offline |

## Tài liệu nguồn

- Wazuh [cài Linux Agent 4.x](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html).
- Wazuh [Suricata integration](https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html).
- Wazuh [agent groups / centralized configuration](https://documentation.wazuh.com/current/user-manual/agent/agent-management/grouping-agents.html).
- Debian [Suricata packages](https://wiki.debian.org/suricata).
- [AI-SOC Linux OneClick](./linux-oneclick.md) và [AI-SOC Server evidence pipeline](https://github.com/chamsocthaytuan/ai_soc/blob/develop/docs/ENDPOINT_EVIDENCE_PIPELINE.md).
