# ESP-Touch for Python

这是乐鑫 ESP-Touch 协议的 Python 实现，用于将 WiFi 凭证配置到 ESP8266/ESP32 设备。该项目是基于 [lib-esptouch-android](https://github.com/EspressifApp/lib-esptouch-android) 的移植版本。

## 功能特点

- 支持 ESP8266 和 ESP32 设备
- 自动获取当前 WiFi 的 SSID 和 BSSID (支持 Windows、macOS 和 Linux)
- 命令行界面和编程接口
- 支持配置多个设备
- 详细日志输出和错误处理

## 安装

1. 确保你安装了 Python 3.6+
2. 克隆本仓库：

```bash
git clone https://github.com/yourusername/EsptouchForPython.git
cd EsptouchForPython
```

3. 安装依赖：

```bash
pip install pycryptodome netifaces
```

注意：`netifaces` 库不是必需的，但它可以提高获取网络接口信息的准确性。

## 使用方法

### 命令行使用

```bash
python esptouch.py [SSID] [BSSID] [PASSWORD] [DEVICE_COUNT]
```

如果不提供参数，脚本将进入交互模式：

```bash
python esptouch.py
```

### 编程接口

```python
from esptouch import configure_esp_device, ESP8266, ESP32

# 配置 ESP8266
results = configure_esp_device(
    ssid="YourWiFiName",
    bssid="XX:XX:XX:XX:XX:XX",
    password="YourWiFiPassword",
    device_count=1,
    device_type=ESP8266  # 或 ESP32
)

for result in results:
    if result.is_success:
        print(f"设备已连接! BSSID: {result.bssid}, IP: {result.ip_address}")
```

### 高级用法

```python
from esptouch import EsptouchTask, NetworkUtils, ESP8266

# 获取当前 WiFi 信息
ssid, bssid = NetworkUtils.get_wifi_info()

# 创建任务
task = EsptouchTask(ssid, bssid, "YourWiFiPassword", ESP8266)

# 设置参数
task.wait_timeout = 30000  # 设置超时时间为 30 秒

# 执行任务
results = task.execute(device_count=2)

# 处理结果
for result in results:
    print(result)
```

## 设备配置说明

1. 确保你的 ESP8266/ESP32 设备已经烧录了支持 ESP-Touch 协议的固件
2. 将设备置于配网模式（通常通过长按按钮或特定操作）
3. 运行此脚本，提供正确的 WiFi 凭证
4. 等待配置完成，设备将连接到指定 WiFi

## 常见问题

1. **无法获取 WiFi 信息**：手动输入 SSID 和 BSSID，BSSID 可以通过路由器管理界面或系统网络设置查看
2. **配置超时**：确保设备已进入配网模式，检查 WiFi 信息是否正确
3. **权限错误**：在某些系统上可能需要管理员权限来访问网络接口

## 贡献

欢迎提交问题报告和改进建议！

## 许可

此项目遵循 MIT 许可证。

## 致谢

感谢乐鑫公司提供的 ESP-Touch 协议和参考实现。 