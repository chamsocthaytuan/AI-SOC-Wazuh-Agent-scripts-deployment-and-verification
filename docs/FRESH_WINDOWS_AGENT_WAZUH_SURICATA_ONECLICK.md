# AI-SOC — Cài Windows Agent từ đầu: Wazuh + Suricata + OneClick Active Response

**Phạm vi:** Windows 10/11 x64, Windows Server tương thích, hoặc FlareVM chạy trên VirtualBox; Wazuh Manager là Ubuntu AI-SOC Server `192.168.100.192`; hướng dẫn dành cho máy **chưa có Wazuh Agent/Suricata**. Cập nhật 06/11/2026.

**Mục tiêu:** Windows endpoint -> Wazuh Agent -> Wazuh Manager / Indexer; tùy chọn Suricata IDS -> EVE JSON -> Wazuh; Active Response scripts từ gói [OneClick Windows v0.1](../windows/oneclick-v0.1/README.md). Chưa khẳng định Verification V2 E2E vì Windows scripts hiện ghi text log chứ chưa emit evidence schema 1.0.

> Không chạy thử cô lập máy qua RDP/SSH mà không có console/snapshot dự phòng. Installer script chỉ cài file, không tự cô lập/chặn IP/kill process. Nếu đã có Agent và `client.keys`, **không cài lại/đăng ký lại**; chuyển sang kiểm tra rồi cài OneClick.

## 1. Kiểm tra server (chỉ chạy trên Ubuntu AI-SOC Server)

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | grep -E 'NAMES|wazuh-manager'
docker exec wazuh-manager /var/ossec/bin/wazuh-control info -v
docker port wazuh-manager | grep -E '1514|1515'
```

Ghi lại **version Wazuh Manager**. Wazuh Agent phải cùng phiên bản hoặc phiên bản được Manager hỗ trợ (Agent không mới hơn Manager). Nếu Manager đang là **4.8.2** như lab trước đây, dùng Agent **4.8.2**, không tải MSI `latest` theo mặc định. Agent cần TCP 1514 để truyền log và thường TCP 1515 để đăng ký.

## 2. Windows PowerShell Administrator — kiểm tra mạng và Agent cũ

```powershell
Get-Service WazuhSvc,wazuh -ErrorAction SilentlyContinue
Test-NetConnection 192.168.100.192 -Port 1514
Test-NetConnection 192.168.100.192 -Port 1515
```

Hai phép kiểm tra cổng cần `TcpTestSucceeded : True`. Nếu không, kiểm tra bridge/NAT VirtualBox, route, firewall và Docker port mapping trên Ubuntu Server; không tắt toàn bộ firewall. Nếu service đã tồn tại, **không cài lại**.

## 3. Cài Wazuh Agent Windows 4.x

Ví dụ **chỉ khi Manager 4.8.2**, dùng PowerShell Administrator:

```powershell
$msi = Join-Path $env:TEMP 'wazuh-agent-4.8.2-1.msi'
Invoke-WebRequest 'https://packages.wazuh.com/4.x/windows/wazuh-agent-4.8.2-1.msi' -OutFile $msi
(Get-FileHash $msi -Algorithm SHA512).Hash
```

Đối chiếu hash với checksum chính thức của package đã chọn trước khi cài. Nếu Manager không phải 4.8.2, thay URL và tên MSI bằng **đúng version tương thích**.

```powershell
$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @('/i', ('"{0}"' -f $msi), '/qn', 'WAZUH_MANAGER=192.168.100.192', 'WAZUH_AGENT_NAME=windows-lab-new')
$p.ExitCode
Start-Service WazuhSvc
Get-Service WazuhSvc
```

MSI trả `0` (thành công) hoặc `3010` (đã cài, yêu cầu restart). Exit code khác: kiểm tra log MSI, không tiếp tục. Không dùng trùng `WAZUH_AGENT_NAME` với endpoint cũ.

**Trên Ubuntu Server**, kiểm tra Agent mới xuất hiện và ghi ID được cấp:

```bash
docker exec wazuh-manager /var/ossec/bin/agent_control -l
```

Nếu Windows Agent đã cài mà chưa `Active`, xem `C:\Program Files (x86)\ossec-agent\ossec.log`, port Manager, và tình trạng enroll. Agent Windows tiêu chuẩn nằm ở `C:\Program Files (x86)\ossec-agent`.

## 4. Cài Suricata IDS trên Windows (tuỳ chọn nhưng hữu ích khi muốn network IDS)

Suricata **không bắt buộc** cho Wazuh Agent/Active Response. Suricata trên Windows có thể dùng bản MSI chính thức; **Npcap** cần thiết để live packet capture. Đây là hướng dẫn **IDS thụ động**, không cấu hình WinDivert/IPS.

1. Tải **Npcap** chính thức từ <https://npcap.com/> và cài driver. Kiểm tra lại điều khoản cấp phép cho môi trường sử dụng.
2. Tải Suricata **Windows 64-bit MSI** từ <https://suricata.io/download/>. Cài bằng quyền Administrator.
3. Mở PowerShell và xác minh thư mục thực tế (có thể khác nếu tùy chọn trong MSI):

```powershell
$suricataHome = 'C:\Program Files\Suricata'
Get-ChildItem $suricataHome -Filter suricata.exe
Get-NetAdapter | Format-Table Name, InterfaceDescription, Status, MacAddress
& "$suricataHome\suricata.exe" -V
```

4. Sao lưu `$suricataHome\suricata.yaml` nếu tồn tại; chỉnh `HOME_NET` phù hợp mạng lab, bật output `eve-log` dưới `outputs` và đặt log directory có quyền ghi của tài khoản chạy Suricata. Chọn **đúng interface bắt gói** theo Npcap/Suricata; tên adapter Windows chưa chắc trùng tên capture interface. Đừng ghi đè toàn bộ YAML bằng một config rút gọn.

```powershell
$config = Join-Path $suricataHome 'suricata.yaml'
Copy-Item $config "$config.bak.$(Get-Date -Format yyyyMMddHHmmss)"
notepad $config
& "$suricataHome\suricata.exe" -T -c $config
```

Nếu `-T` không thành công, sửa cấu hình/rules trước khi bật bắt gói. Với card mạng đã xác định, thử Suricata **ở console** theo cú pháp `suricata.exe -c <config> -i <interface>` của phiên bản đang cài; việc cài/kích hoạt Windows service phụ thuộc MSI/phiên bản, **đừng giả định service đã có**. Khởi chạy Suricata dưới quyền đủ để Npcap capture; nếu cần chạy liên tục, cấu hình Windows service theo tài liệu phiên bản sử dụng và kiểm tra service thực tế.

Tìm file EVE JSON **theo cấu hình thực**:

```powershell
Get-ChildItem 'C:\Program Files\Suricata','C:\Suricata' -Filter eve.json -Recurse -ErrorAction SilentlyContinue |
  Select-Object FullName, Length, LastWriteTime
```

Không có file `eve.json` thì chưa được tính là tích hợp Suricata. Kiểm tra đường dẫn, quyền ghi log, capture interface và có traffic trước khi tiếp tục.

## 5. Cho Windows Wazuh Agent đọc Suricata eve.json

Trên Windows Agent, PowerShell Administrator, sao lưu `ossec.conf`:

```powershell
$ossec = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
Copy-Item $ossec "$ossec.bak.$(Get-Date -Format yyyyMMddHHmmss)"
notepad $ossec
```

Trong block `<ossec_config>` hiện hữu, thêm đúng **một** block `<localfile>` và thay `<EVE_JSON_FULL_PATH>` bằng đường dẫn thực tế từ bước 4:

```xml
<localfile>
  <log_format>json</log_format>
  <location>C:\Program Files\Suricata\log\eve.json</location>
</localfile>
```

Đường dẫn ví dụ trên **chỉ đúng khi file thật ở đó**. Giữ nguyên phần `client/server` và mọi cấu hình khác. Kiểm tra XML rồi restart:

```powershell
[xml]$null = Get-Content $ossec -Raw
Restart-Service WazuhSvc
Get-Service WazuhSvc
```

Wazuh sẽ nhận JSON logs từ Suricata. Sự kiện `event_type=alert` chỉ xuất hiện khi có lưu lượng khớp rules. **Rule 119910 không dành cho Suricata**: nó là rule của evidence Active Response Linux V2.

## 6. Cài AI-SOC Windows Active Response OneClick

Bộ cài đã có trong GitHub branch `script-windows`, tại [windows/oneclick-v0.1](../windows/oneclick-v0.1/). Tải [ZIP](../windows/oneclick-v0.1/AI-SOC-Windows-AR-OneClick-v0.1.zip) và giải nén vào thư mục trống, ví dụ `C:\AI-SOC-Windows-AR-OneClick`.

Mở Windows PowerShell 5.1 **Run as Administrator** trong thư mục đã giải nén:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-AISOCWindowsAR.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-AISOCWindowsAR.ps1 -Apply
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-AISOCWindowsAR.ps1
```

Chạy từng lệnh theo thứ tự: **preview → apply → test**. Installer tự tìm Wazuh Agent, sao lưu script trước khi ghi đè, cài 9 file payload vào `active-response\bin`, sửa wrapper `.cmd`, kiểm tra hash và restart Agent nếu trước đó Agent đang chạy. Dòng báo mong đợi `INSTALL_OK` và `STATIC_CHECK_OK`.

Nếu cần phục hồi, dùng đúng thư mục `BACKUP` mà installer in ra, tham khảo [README của gói](../windows/oneclick-v0.1/README.md). Tránh kích hoạt isolate/kill trong lúc đang cài đặt.

## 7. Cấu hình trên Ubuntu Manager (bước riêng)

Cài OneClick vào Windows Agent **không tự đăng ký custom Active Response commands** lên Ubuntu Wazuh Manager. Bộ Windows chứa template cho 3 command:

- `ai-soc-win-block-ip` → `block-ip-win.cmd`
- `ai-soc-win-isolate` → `isolate-host.cmd`
- `ai-soc-win-kill-process` → `kill-process-win.cmd`

Có script [manager/register-manager-commands.py](../windows/oneclick-v0.1/manager/register-manager-commands.py) để thêm 3 `<command>` vào **file ossec.conf thực tế được bind-mount** trên Ubuntu server, có backup và preview. Dùng sau khi xác định chắc chắn file nào Manager đang nạp; **không chạy trên file config mẫu rồi tưởng đã áp dụng**.

```bash
# Trên Ubuntu Server, xem mount trước, tìm đúng ossec.conf thật
docker inspect wazuh-manager --format '{{json .Mounts}}'
# Khi đã xác định đường dẫn host thật:
python3 manager/register-manager-commands.py --config /ACTUAL/HOST/PATH/ossec.conf
python3 manager/register-manager-commands.py --config /ACTUAL/HOST/PATH/ossec.conf --apply
docker exec wazuh-manager /var/ossec/bin/wazuh-analysisd -t
```

`manager/register-manager-commands.py` là script nằm trong gói OneClick Windows; chạy nó từ thư mục chứa file trên Ubuntu, ví dụ sau khi tải/giải nén gói. Lên lịch restart Manager sau khi kiểm tra cấu hình, tránh làm gián đoạn Agent khi lab đang vận hành. **Không cấu hình trigger tự động cho isolate**, chỉ dùng dispatch có phê duyệt đến một Agent được chỉ định.

## 8. Kiểm tra nghiệm thu

**Windows Agent:**

```powershell
Get-Service WazuhSvc
Test-NetConnection 192.168.100.192 -Port 1514
Get-ChildItem 'C:\Program Files (x86)\ossec-agent\active-response\bin\*win*.cmd'
```

Kiểm tra Suricata có `eve.json` và file có cập nhật; `Get-Service Suricata` chỉ có ý nghĩa nếu đã cài thành Windows service.

**Ubuntu Server:**

```bash
docker exec wazuh-manager /var/ossec/bin/agent_control -l
docker exec wazuh-manager /var/ossec/bin/wazuh-analysisd -t
```

Chỉ khi Agent xuất hiện `Active`, Windows OneClick trả `STATIC_CHECK_OK`, Manager runtime có command và Suricata có EVE JSON (nếu sử dụng) thì coi như **hoàn tất phần cài/cấu hình cơ bản**.

**Chưa được kết luận `VERIFIED` trên AI-SOC Center** chỉ từ các bước này. Windows OneClick v0.1 ghi `active-responses.log` text, chưa xuất `schema_version=1.0` với `execution_id`, `event_id`, `boot_id` để Verification V2 qua rule 119910, Indexer và evidence ledger. Phải nâng cấp evidence producer và làm test E2E riêng trước khi công bố Windows Verification V2 đã đạt.

## Tài liệu tham khảo

- [Wazuh Windows Agent installer](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html)
- [Wazuh monitoring local files](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/monitoring-log-files.html)
- [Suricata Windows download](https://suricata.io/download/)
- [Suricata Windows build/end-user prerequisite: Npcap](https://docs.suricata.io/en/latest/install/windows.html)
- [AI-SOC Windows OneClick v0.1](../WINDOWS-ONECLICK.md)
