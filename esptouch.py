#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ESP-Touch 协议的 Python 实现

基于乐鑫 ESP-Touch Android 库的移植版本
https://github.com/EspressifApp/lib-esptouch-android

本代码用于将 WiFi 凭证发送给 ESP8266/ESP32 设备
"""

import socket
import time
import struct
import binascii
import threading
import logging
import platform
import sys
from typing import List, Dict, Tuple, Optional, Union, Any

# 配置日志记录
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('esptouch')

try:
    from Crypto.Cipher import AES  # 需要安装 pycryptodome 库
    HAS_CRYPTO = True
except ImportError:
    logger.warning("未找到 pycryptodome 库，AES 加密将不可用")
    HAS_CRYPTO = False

try:
    import netifaces
    HAS_NETIFACES = True
except ImportError:
    logger.warning("未找到 netifaces 库，获取网络接口信息可能受限")
    HAS_NETIFACES = False

# 设备类型
ESP8266 = "ESP8266"
ESP32 = "ESP32"

class EsptouchResult:
    """ESP-Touch 配置结果类"""
    
    def __init__(self, is_success: bool, bssid: str, ip_address: str):
        self.is_success = is_success
        self.bssid = bssid
        self.ip_address = ip_address
        self.is_cancelled = False
    
    def __str__(self) -> str:
        return f"配置结果: 成功={self.is_success}, BSSID={self.bssid}, IP={self.ip_address}"

class CRC8:
    """CRC8实现，对应Java版本的CRC8类"""
    
    def __init__(self):
        self.crc_table = []
        self.CRC_POLYNOM = 0x8c
        self._generate_crc_table()
        self.value = 0x00
        
    def _generate_crc_table(self):
        """生成CRC表"""
        for dividend in range(256):
            remainder = dividend
            for bit in range(8):
                if remainder & 0x01:
                    remainder = (remainder >> 1) ^ self.CRC_POLYNOM
                else:
                    remainder = remainder >> 1
            self.crc_table.append(remainder & 0xff)
            
    def update(self, data):
        """更新CRC值"""
        if isinstance(data, bytes):
            for b in data:
                data_byte = b ^ self.value
                self.value = (self.crc_table[data_byte & 0xff] ^ (self.value << 8)) & 0xff
        else:
            data_byte = data ^ self.value
            self.value = (self.crc_table[data_byte & 0xff] ^ (self.value << 8)) & 0xff
            
    def get_value(self):
        """获取CRC值"""
        return self.value & 0xff
        
    def reset(self):
        """重置CRC值"""
        self.value = 0x00

class TouchEncryptor:
    """AES加密实现，对应Java版本的TouchAES类"""
    
    def __init__(self, key: bytes):
        """
        初始化加密器
        
        Args:
            key: AES密钥，长度必须为16、24或32字节
        """
        if not HAS_CRYPTO:
            raise RuntimeError("需要安装 pycryptodome 库以支持加密")
            
        self.key = key
        self.cipher = AES.new(key, AES.MODE_ECB)
        
    def encrypt(self, data: bytes) -> bytes:
        """
        加密数据
        
        Args:
            data: 要加密的数据
            
        Returns:
            加密后的数据
        """
        # 确保数据长度是16字节的倍数
        pad_len = 16 - (len(data) % 16)
        padded_data = data + bytes([pad_len]) * pad_len
        return self.cipher.encrypt(padded_data)

class DataCode:
    """数据编码实现，对应Java版本的DataCode类"""
    
    DATA_CODE_LEN = 6
    INDEX_MAX = 127
    
    def __init__(self, char_value: int, index: int):
        """
        初始化数据编码
        
        Args:
            char_value: 字符值 (0-255)
            index: 索引值 (0-127)
        """
        if index > self.INDEX_MAX:
            raise ValueError(f"index > INDEX_MAX ({self.INDEX_MAX})")
        
        self.seq_header = index
        # 分割uint8为高位和低位
        self.data_high = (char_value >> 4) & 0x0f
        self.data_low = char_value & 0x0f
        
        # 计算CRC
        crc8 = CRC8()
        crc8.update(char_value)
        crc8.update(index)
        crc_value = crc8.get_value()
        self.crc_high = (crc_value >> 4) & 0x0f
        self.crc_low = crc_value & 0x0f
        
    def get_bytes(self) -> bytes:
        """获取字节序列"""
        data_bytes = bytearray(self.DATA_CODE_LEN)
        data_bytes[0] = 0x00
        data_bytes[1] = (self.crc_high << 4) | self.data_high
        data_bytes[2] = 0x01
        data_bytes[3] = self.seq_header
        data_bytes[4] = 0x00
        data_bytes[5] = (self.crc_low << 4) | self.data_low
        return bytes(data_bytes)

class DatumCode:
    """数据码集合实现，对应Java版本的DatumCode类"""
    
    EXTRA_HEAD_LEN = 5
    EXTRA_LEN = 40
    
    def __init__(self, ap_ssid: bytes, ap_bssid: bytes, ap_password: bytes, ip_address: str, encryptor=None):
        """
        初始化数据码
        
        Args:
            ap_ssid: AP的SSID
            ap_bssid: AP的BSSID
            ap_password: AP的密码
            ip_address: 本机IP地址
            encryptor: 可选的加密器
        """
        self.data_codes = []
        
        # 计算各种长度和CRC
        total_xor = 0
        ap_password_len = len(ap_password)
        
        crc = CRC8()
        crc.update(ap_ssid)
        ap_ssid_crc = crc.get_value()
        
        crc.reset()
        crc.update(ap_bssid)
        ap_bssid_crc = crc.get_value()
        
        ap_ssid_len = len(ap_ssid)
        ip_bytes = socket.inet_aton(ip_address)
        ip_len = len(ip_bytes)
        
        total_len = self.EXTRA_HEAD_LEN + ip_len + ap_password_len + ap_ssid_len
        
        # 构建数据码
        self.data_codes.append(DataCode(total_len, 0))
        total_xor ^= total_len
        
        self.data_codes.append(DataCode(ap_password_len, 1))
        total_xor ^= ap_password_len
        
        self.data_codes.append(DataCode(ap_ssid_crc, 2))
        total_xor ^= ap_ssid_crc
        
        self.data_codes.append(DataCode(ap_bssid_crc, 3))
        total_xor ^= ap_bssid_crc
        
        # IP地址
        for i, b in enumerate(ip_bytes):
            total_xor ^= b
            self.data_codes.append(DataCode(b, i + self.EXTRA_HEAD_LEN))
        
        # 密码
        for i, b in enumerate(ap_password):
            total_xor ^= b
            self.data_codes.append(DataCode(b, i + self.EXTRA_HEAD_LEN + ip_len))
        
        # SSID
        for i, b in enumerate(ap_ssid):
            total_xor ^= b
            self.data_codes.append(DataCode(b, i + self.EXTRA_HEAD_LEN + ip_len + ap_password_len))
        
        # 添加总校验和
        self.data_codes.insert(4, DataCode(total_xor, 4))
        
        # 添加BSSID
        bssid_insert_index = self.EXTRA_HEAD_LEN
        for i, b in enumerate(ap_bssid):
            index = total_len + i
            dc = DataCode(b, index)
            if bssid_insert_index >= len(self.data_codes):
                self.data_codes.append(dc)
            else:
                self.data_codes.insert(bssid_insert_index, dc)
            bssid_insert_index += 4
    
    def get_bytes(self) -> bytes:
        """获取字节序列"""
        datum_code = bytearray()
        for dc in self.data_codes:
            datum_code.extend(dc.get_bytes())
        return bytes(datum_code)
        
    def get_u8s(self) -> List[int]:
        """
        获取u8数组
        
        Returns:
            u8数组
        """
        data_bytes = self.get_bytes()
        len_data = len(data_bytes) // 2
        data_u8s = []
        
        for i in range(len_data):
            high = data_bytes[i * 2]
            low = data_bytes[i * 2 + 1]
            # 组合高低位，并加上额外长度
            u8 = ((high << 8) | low) + self.EXTRA_LEN
            data_u8s.append(u8)
            
        return data_u8s

class GuideCode:
    """引导码实现，对应Java版本的GuideCode类"""
    
    GUIDE_CODE_LEN = 4
    
    def get_u8s(self) -> List[int]:
        """
        获取u8数组
        
        Returns:
            u8数组
        """
        return [515, 514, 513, 512]

class EsptouchGenerator:
    """ESP-Touch配置数据生成器，对应Java版本的EsptouchGenerator类"""
    
    def __init__(self, ap_ssid: bytes, ap_bssid: bytes, ap_password: bytes, ip_address: str, encryptor=None):
        """
        初始化生成器
        
        Args:
            ap_ssid: AP的SSID
            ap_bssid: AP的BSSID
            ap_password: AP的密码
            ip_address: 本机IP地址
            encryptor: 可选的加密器
        """
        # 生成引导码
        gc = GuideCode()
        self.gc_u8s = gc.get_u8s()
        self.gc_bytes = []
        
        for u8 in self.gc_u8s:
            self.gc_bytes.append(bytes([ord('1')] * u8))
        
        # 生成数据码
        dc = DatumCode(ap_ssid, ap_bssid, ap_password, ip_address, encryptor)
        self.dc_u8s = dc.get_u8s()
        self.dc_bytes = []
        
        # 从DatumCode获取数据并转换为发送格式
        for u8 in self.dc_u8s:
            self.dc_bytes.append(bytes([ord('1')] * u8))
            
    def get_guide_code_bytes(self) -> List[bytes]:
        """获取引导码字节序列"""
        return self.gc_bytes
        
    def get_data_code_bytes(self) -> List[bytes]:
        """获取数据码字节序列"""
        return self.dc_bytes

class UDPSocketClient:
    """UDP客户端实现，对应Java版本的UDPSocketClient类"""
    
    def __init__(self):
        """初始化UDP客户端"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.is_stopped = False
        except socket.error as e:
            logger.error(f"创建UDP客户端失败: {e}")
            raise
    
    def send_data(self, data: List[bytes], target_host: str, target_port: int, interval: int) -> None:
        """
        发送数据
        
        Args:
            data: 要发送的数据列表
            target_host: 目标主机
            target_port: 目标端口
            interval: 发送间隔(毫秒)
        """
        if not data or len(data) == 0:
            logger.warning("没有数据可发送")
            return
        
        logger.debug(f"准备发送数据到 {target_host}:{target_port}, 间隔: {interval}ms")
        
        for i in range(len(data)):
            if self.is_stopped or not data[i]:
                continue
                
            try:
                self.socket.sendto(data[i], (target_host, target_port))
            except Exception as e:
                logger.error(f"发送数据失败: {e}")
                self.is_stopped = True
                break
                
            try:
                time.sleep(interval / 1000)  # 毫秒转换为秒
            except InterruptedError:
                logger.warning("发送过程被中断")
                self.is_stopped = True
                break
                
        logger.debug("数据发送完成")
    
    def interrupt(self) -> None:
        """中断发送"""
        logger.debug("中断UDP客户端")
        self.is_stopped = True
    
    def close(self) -> None:
        """关闭套接字"""
        logger.debug("关闭UDP客户端")
        self.socket.close()

class UDPSocketServer:
    """UDP服务器实现，对应Java版本的UDPSocketServer类"""
    
    def __init__(self, port: int, timeout: int):
        """
        初始化UDP服务器
        
        Args:
            port: 监听端口
            timeout: 超时时间(毫秒)
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('0.0.0.0', port))
            self.socket.settimeout(timeout / 1000)  # 毫秒转换为秒
            logger.debug(f"UDP服务器已启动于端口 {port}, 超时: {timeout}ms")
        except socket.error as e:
            logger.error(f"创建UDP服务器失败: {e}")
            raise
        
    def receive_specific_length(self, length: int) -> Optional[bytes]:
        """
        接收指定长度的数据
        
        Args:
            length: 期望的数据长度
            
        Returns:
            接收到的数据，如果超时或错误则返回None
        """
        try:
            data, addr = self.socket.recvfrom(64)
            logger.debug(f"从 {addr} 接收到数据，长度: {len(data)}")
            if len(data) != length:
                logger.debug(f"数据长度不匹配，期望 {length}，实际 {len(data)}")
                return None
            return data
        except socket.timeout:
            # 超时不记录错误
            return None
        except Exception as e:
            logger.error(f"接收数据失败: {e}")
            return None
            
    def set_timeout(self, timeout: int) -> bool:
        """
        设置超时时间
        
        Args:
            timeout: 超时时间(毫秒)
            
        Returns:
            设置是否成功
        """
        try:
            self.socket.settimeout(timeout / 1000)  # 毫秒转换为秒
            return True
        except socket.error as e:
            logger.error(f"设置超时失败: {e}")
            return False
            
    def close(self) -> None:
        """关闭套接字"""
        logger.debug("关闭UDP服务器")
        self.socket.close()

class NetworkUtils:
    """网络工具类，用于处理网络相关操作"""
    
    @staticmethod
    def get_local_ip(wifi_interface=None) -> str:
        """
        获取本机IP地址
        
        Args:
            wifi_interface: 指定的WiFi接口名称，如果为None则自动检测
            
        Returns:
            本机IP地址
        """
        # 尝试使用netifaces库获取接口信息
        if HAS_NETIFACES:
            try:
                # 如果指定了接口
                if wifi_interface:
                    if wifi_interface in netifaces.interfaces():
                        addresses = netifaces.ifaddresses(wifi_interface)
                        if netifaces.AF_INET in addresses:
                            return addresses[netifaces.AF_INET][0]['addr']
                
                # 否则自动检测
                for interface in netifaces.interfaces():
                    # 跳过回环接口
                    if interface == 'lo' or interface.startswith('lo'):
                        continue
                    
                    addresses = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addresses:
                        for link in addresses[netifaces.AF_INET]:
                            ip = link['addr']
                            # 忽略回环地址
                            if not ip.startswith('127.'):
                                logger.debug(f"从接口 {interface} 获取到IP: {ip}")
                                return ip
            except Exception as e:
                logger.warning(f"使用netifaces获取IP地址失败: {e}")
        
        # 回退方法1：使用socket获取
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # 不需要真正连接
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            logger.debug(f"从socket获取到IP: {ip}")
            return ip
        except Exception as e:
            logger.warning(f"使用socket获取IP地址失败: {e}")
        
        # 回退方法2：本地IP
        logger.warning("无法获取真实IP地址，使用127.0.0.1")
        return '127.0.0.1'
    
    @staticmethod
    def get_wifi_info() -> Tuple[Optional[str], Optional[str]]:
        """
        尝试获取当前WiFi的SSID和BSSID
        
        Returns:
            (ssid, bssid)元组，如果获取失败则返回(None, None)
        """
        system = platform.system()
        
        if system == 'Darwin':  # macOS
            try:
                # 获取当前WiFi接口的SSID
                import subprocess
                output = subprocess.check_output(
                    ['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-I'],
                    universal_newlines=True
                )
                
                ssid = None
                bssid = None
                
                for line in output.split('\n'):
                    if ' SSID: ' in line:
                        ssid = line.split(' SSID: ')[1].strip()
                    elif ' BSSID: ' in line:
                        bssid = line.split(' BSSID: ')[1].strip()
                
                if ssid and bssid:
                    return ssid, bssid
            except Exception as e:
                logger.warning(f"获取macOS WiFi信息失败: {e}")
                
        elif system == 'Linux':
            try:
                # 尝试使用iwconfig
                import subprocess
                output = subprocess.check_output(['iwconfig'], universal_newlines=True, stderr=subprocess.STDOUT)
                
                interface = None
                ssid = None
                bssid = None
                
                for line in output.split('\n'):
                    if ' ESSID:' in line:
                        interface = line.split(' ')[0]
                        ssid = line.split('ESSID:')[1].strip('"')
                    if 'Access Point:' in line and interface:
                        bssid = line.split('Access Point:')[1].strip()
                        break
                
                if ssid and bssid:
                    return ssid, bssid
            except Exception as e:
                logger.warning(f"获取Linux WiFi信息失败: {e}")
                
        elif system == 'Windows':
            try:
                # 使用netsh
                import subprocess
                output = subprocess.check_output(['netsh', 'wlan', 'show', 'interfaces'], universal_newlines=True)
                
                ssid = None
                bssid = None
                
                for line in output.split('\n'):
                    if 'SSID' in line and 'BSSID' not in line:
                        ssid = line.split(':')[1].strip()
                    elif 'BSSID' in line:
                        bssid = line.split(':')[1].strip()
                
                if ssid and bssid:
                    return ssid, bssid
            except Exception as e:
                logger.warning(f"获取Windows WiFi信息失败: {e}")
        
        logger.warning("无法自动获取WiFi信息")
        return None, None
    
    @staticmethod
    def parse_bssid(bssid_str: str) -> bytes:
        """
        解析BSSID字符串为字节数组
        
        Args:
            bssid_str: BSSID字符串，格式为XX:XX:XX:XX:XX:XX
            
        Returns:
            BSSID字节数组
        """
        try:
            return bytes.fromhex(bssid_str.replace(':', ''))
        except Exception as e:
            raise ValueError(f"BSSID格式无效: {bssid_str}, 错误: {e}")

class EsptouchTask:
    """ESP-Touch主任务，用于配置ESP8266/ESP32设备"""
    
    def __init__(self, ap_ssid: str, ap_bssid: str, ap_password: str, device_type=ESP8266):
        """
        初始化ESP-Touch任务
        
        Args:
            ap_ssid: AP的SSID
            ap_bssid: AP的BSSID（格式为XX:XX:XX:XX:XX:XX）
            ap_password: AP的密码
            device_type: 设备类型，默认为ESP8266
        """
        if not ap_ssid:
            raise ValueError("SSID不能为空")
        if not ap_bssid:
            raise ValueError("BSSID不能为空")
            
        # 参数初始化
        self.ap_ssid = ap_ssid.encode('utf-8')
        self.ap_bssid = NetworkUtils.parse_bssid(ap_bssid)
        self.ap_password = ap_password.encode('utf-8')
        self.device_type = device_type
        
        # 获取本机IP
        self.local_ip = NetworkUtils.get_local_ip()
        logger.info(f"使用本机IP: {self.local_ip}")
        
        # 参数配置
        self.port_listening = 18266
        self.target_port = 7001
        self.broadcast_address = "255.255.255.255"
        self.wait_timeout = 60000  # 60秒超时
        self.interval_guide_code_millisecond = 8
        self.interval_data_code_millisecond = 8
        self.total_repeat_time = 1
        
        # 结果存储
        self.esptouch_results = []
        self.is_cancelled = False
        self.is_broadcast_mode = True
        
    def set_broadcast(self, broadcast: bool) -> None:
        """
        设置使用广播或组播
        
        Args:
            broadcast: True使用广播，False使用组播
        """
        self.is_broadcast_mode = broadcast
        
    def get_target_hostname(self) -> str:
        """
        获取目标主机名
        
        Returns:
            目标主机名
        """
        if self.is_broadcast_mode:
            return self.broadcast_address
        else:
            # 组播地址，与Java版本保持一致
            count = 1  # 简化，不用生成随机数
            return f"234.{count}.{count}.{count}"
        
    def _broadcast_task(self) -> None:
        """广播ESP-Touch配置数据的任务"""
        logger.info("开始广播ESP-Touch配置数据")
        socket_client = UDPSocketClient()
        
        try:
            # 生成配置数据
            generator = EsptouchGenerator(
                self.ap_ssid, 
                self.ap_bssid, 
                self.ap_password, 
                self.local_ip
            )
            
            for i in range(self.total_repeat_time):
                if self.is_cancelled:
                    logger.info("广播任务被取消")
                    break
                    
                # 发送引导码
                logger.debug("发送引导码")
                socket_client.send_data(
                    generator.get_guide_code_bytes(),
                    self.get_target_hostname(),
                    self.target_port,
                    self.interval_guide_code_millisecond
                )
                
                # 发送数据码
                logger.debug("发送数据码")
                socket_client.send_data(
                    generator.get_data_code_bytes(),
                    self.get_target_hostname(),
                    self.target_port,
                    self.interval_data_code_millisecond
                )
                
            logger.info("广播ESP-Touch配置数据完成")
        except Exception as e:
            logger.error(f"广播ESP-Touch配置数据失败: {e}")
        finally:
            socket_client.close()
    
    def _listen_task(self) -> None:
        """监听ESP设备响应的任务"""
        logger.info(f"开始监听ESP设备响应，端口: {self.port_listening}")
        socket_server = UDPSocketServer(self.port_listening, self.wait_timeout)
        
        try:
            start_time = time.time()
            while (time.time() - start_time) * 1000 < self.wait_timeout:
                if self.is_cancelled:
                    logger.info("监听任务被取消")
                    break
                    
                # 监听设备响应，根据经验响应数据长度为11
                expected_len = 11
                data = socket_server.receive_specific_length(expected_len)
                
                if data:
                    try:
                        # 解析接收到的数据，获取BSSID和IP
                        bssid = binascii.hexlify(data[1:7]).decode()
                        ip = socket.inet_ntoa(data[7:11])
                        
                        # 添加到结果列表
                        result = EsptouchResult(True, bssid, ip)
                        self.esptouch_results.append(result)
                        
                        logger.info(f"设备已连接: BSSID={bssid}, IP={ip}")
                    except Exception as e:
                        logger.error(f"解析设备响应失败: {e}")
                        
            if not self.esptouch_results:
                # 如果没有设备响应，添加一个失败结果
                logger.warning("没有设备响应")
                result = EsptouchResult(False, "", "")
                self.esptouch_results.append(result)
                
        except Exception as e:
            logger.error(f"监听ESP设备响应失败: {e}")
        finally:
            socket_server.close()
        
    def execute(self, device_count=1) -> List[EsptouchResult]:
        """
        执行ESP-Touch任务
        
        Args:
            device_count: 期望配置的设备数量
            
        Returns:
            ESP-Touch结果列表
        """
        if device_count <= 0:
            device_count = 1
            
        logger.info(f"执行ESP-Touch任务，SSID: {self.ap_ssid.decode()}, BSSID: {binascii.hexlify(self.ap_bssid).decode()}")
        
        # 检查是否有效
        if self.is_cancelled:
            self.is_cancelled = False
            
        # 启动广播线程
        broadcast_thread = threading.Thread(target=self._broadcast_task)
        broadcast_thread.daemon = True
        broadcast_thread.start()
        
        # 启动监听线程
        listen_thread = threading.Thread(target=self._listen_task)
        listen_thread.daemon = True
        listen_thread.start()
        
        try:
            # 等待所有线程完成或者结果达到预期数量
            while broadcast_thread.is_alive() or listen_thread.is_alive():
                if len([r for r in self.esptouch_results if r.is_success]) >= device_count:
                    logger.info(f"已获取到 {device_count} 个成功结果，停止任务")
                    self.cancel()
                    break
                time.sleep(0.1)
        except KeyboardInterrupt:
            logger.info("任务被用户中断")
            self.cancel()
        
        logger.info(f"ESP-Touch任务执行完成，结果数量: {len(self.esptouch_results)}")
        return self.esptouch_results
        
    def cancel(self) -> None:
        """取消任务"""
        logger.info("取消ESP-Touch任务")
        self.is_cancelled = True

def configure_esp_device(ssid: str, bssid: str, password: str, device_count=1, device_type=ESP8266) -> List[EsptouchResult]:
    """
    配置ESP设备连接WiFi
    
    Args:
        ssid: WiFi的SSID
        bssid: WiFi的BSSID
        password: WiFi的密码
        device_count: 需要配置的设备数量
        device_type: 设备类型
        
    Returns:
        设备配置结果列表
    """
    task = EsptouchTask(ssid, bssid, password, device_type)
    results = task.execute(device_count)
    return results

def show_wifi_info() -> Tuple[Optional[str], Optional[str]]:
    """
    显示当前WiFi信息
    
    Returns:
        (ssid, bssid)元组
    """
    ssid, bssid = NetworkUtils.get_wifi_info()
    if ssid and bssid:
        print(f"当前WiFi信息: SSID={ssid}, BSSID={bssid}")
    else:
        print("无法获取当前WiFi信息")
    return ssid, bssid

if __name__ == "__main__":
    # 设置日志级别
    logging.getLogger('esptouch').setLevel(logging.INFO)
    
    print("ESP-Touch配置工具 v1.0")
    print("-------------------------------")
    
    # 尝试获取当前WiFi信息
    current_ssid, current_bssid = show_wifi_info()
    
    if len(sys.argv) >= 4:
        # 命令行参数模式
        ssid = sys.argv[1]
        bssid = sys.argv[2]
        password = sys.argv[3]
        device_count = int(sys.argv[4]) if len(sys.argv) >= 5 else 1
    else:
        # 交互式模式
        ssid = input(f"请输入WiFi SSID [{current_ssid}]: ").strip() if current_ssid else input("请输入WiFi SSID: ").strip()
        if not ssid and current_ssid:
            ssid = current_ssid
            
        bssid = input(f"请输入WiFi BSSID [{current_bssid}]: ").strip() if current_bssid else input("请输入WiFi BSSID (格式为XX:XX:XX:XX:XX:XX): ").strip()
        if not bssid and current_bssid:
            bssid = current_bssid
            
        password = input("请输入WiFi密码: ").strip()
        
        device_count_input = input("请输入需要配置的设备数量 [1]: ").strip()
        device_count = int(device_count_input) if device_count_input else 1
    
    if not ssid or not bssid:
        print("错误: SSID和BSSID不能为空")
        sys.exit(1)
        
    print(f"\n正在配置ESP设备连接WiFi: SSID={ssid}, BSSID={bssid}")
    print("请确保ESP设备已进入配网模式...\n")
    
    try:
        results = configure_esp_device(ssid, bssid, password, device_count)
        
        success_count = sum(1 for r in results if r.is_success)
        print(f"\n配置完成，成功设备数: {success_count}/{len(results)}")
        
        for i, result in enumerate(results):
            if result.is_success:
                print(f"设备 {i+1}: BSSID={result.bssid}, IP={result.ip_address}")
    except Exception as e:
        print(f"配置过程中发生错误: {e}")
        sys.exit(1) 