from bs4 import BeautifulSoup
from urllib.parse import urlsplit, parse_qs, unquote
from pathlib import Path
from curl_cffi import requests
import json
import numpy as np
import random
import re
import requests as orequests
import socket
import subprocess
import tempfile
import time
import base64
import shutil
from colorama import init, Fore, Back, Style

init()


# Цвета и вывод в консоль

FOREGROUND = [
    Fore.BLACK,
    Fore.RED,
    Fore.GREEN,
    Fore.YELLOW,
    Fore.BLUE,
    Fore.MAGENTA,
    Fore.CYAN,
    Fore.WHITE,
]

BACKGROUND = [
    Back.BLACK,
    Back.RED,
    Back.GREEN,
    Back.YELLOW,
    Back.BLUE,
    Back.MAGENTA,
    Back.CYAN,
    Back.WHITE,
]

BRIGHTNESS = [Style.DIM, Style.NORMAL, Style.BRIGHT]


def print_with_color(s, color=Fore.WHITE, brightness=Style.NORMAL, **kwargs):
    """Печатает сообщение с заданными цветом и яркостью."""
    print(f"{brightness}{color}{s}{Style.RESET_ALL}", **kwargs)

def encodeb64(input: str):
    input_bytes = input.encode("utf-8")
    
    base64_bytes = base64.b64encode(input_bytes)
    return base64_bytes.decode("utf-8")

def decodeb64(input: str):
    input_bytes = input.encode("utf-8")
    
    base64_bytes = base64.b64decode(input_bytes)
    return base64_bytes.decode("utf-8")

class FileStorageSet:
    """Хранит уникальные строки и записывает новые значения в файл."""

    def __init__(self, filename: str):
        self.__storage = set()

        try:
            self.__file = open(filename, "r")

            for line in self.__file.readlines():
                line = line.strip()
                if line:
                    self.__storage.add(decodeb64(line))

            self.__file.close()
        except FileNotFoundError:
            pass

        self.__file = open(filename, "a")

    def add(self, line: str):
        if line in self.__storage:
            return

        self.__storage.add(line)
        self.__file.write(f"{encodeb64(line)}\n")
        self.__file.flush()

    @property
    def storage(self):
        return frozenset(self.__storage)

    def __del__(self):
        self.__file.flush()
        self.__file.close()


class StatusBar:
    """Выводит прогресс и сообщения над строкой состояния."""

    def __init__(self, width: int, max_value: int, /):
        self.__width = max(width - 9, 20) # len("[] 100%") == 7
        self.__max_value = max_value
        self.__value = 0

        print("")  # Резервируем место для вывода статус бара
        self.__update()

    def __clear(self):
        print("\033[F\033[K", end="")

    def __update(self):
        filled_len = min(
            (self.__width * self.__value) // self.__max_value, self.__width
        )
        tail_len = self.__width - filled_len

        percent = (self.__value * 100) // self.__max_value

        self.__clear()
        print(f"[{'#' * filled_len}{'-' * tail_len}] {percent}%")

    @property
    def value(self):
        return self.__value

    @value.setter
    def value(self, value: int):
        self.__value = np.clip(value, 0, self.__max_value)

        self.__update()

    @property
    def max_value(self):
        return self.__max_value

    @max_value.setter
    def max_value(self, max_value: int):
        self.__max_value = max(0, max_value)
        self.__value = np.clip(self.__value, 0, self.__max_value)

        self.__update()

    def print(self, *args):
        self.__clear()
        print(*args, "\n")
        self.__update()


# Настройки приложения

config_filename = "./config.json"
used_vpn_links_filename = "./used_vpn_links.txt"

with open(config_filename, "r", encoding="utf-8") as f:
    poller_config = json.load(f)

# Параметры из config.json

SOCKS_PORT = poller_config.get("SOCKS_PORT", 10808)
disable_sing_box_log = poller_config["disable_sing_box_log"]
vpn_links = poller_config["vpn_list_links"]
vpn_configs_update_pause = int(
    poller_config.get("vpn_configs_update_pause", 15)) * 60
time_for_vote = int(poller_config.get("time_for_vote", 15))
target_person_name = poller_config["target_person_name"]
max_successful_vote = poller_config["max_successful_vote"]
pause_between_vote = poller_config["pause_between_vote"]
vpn_check_timeout = poller_config["vpn_check_timeout"]


# Конфигурация sing-box и разбор VPN-ссылок


def make_config(outbound: dict, port: int) -> dict:
    """Создаёт конфигурацию sing-box с локальным SOCKS-прокси."""

    return {
        "log": {
            "disabled": disable_sing_box_log,
            "level": "error",
            "timestamp": True
        },

        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": port,
            }
        ],
        "outbounds": [outbound],
        "route": {"final": "proxy"},
    }


def vless_extractor(uri: str) -> dict:
    """Преобразует VLESS-ссылку в outbound для sing-box."""

    u = urlsplit(uri)

    if u.scheme != "vless":
        raise ValueError("Ожидался vless:// URI")

    uuid = unquote(u.username or "")
    host = u.hostname
    port = u.port

    if not uuid or not host or not port:
        raise ValueError("В URI отсутствуют UUID, host или port")

    q = {key: values[0] for key, values in parse_qs(u.query).items()}

    outbound = {
        "type": "vless",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "uuid": uuid,
    }

    # VLESS Vision
    if flow := q.get("flow"):
        outbound["flow"] = flow

    # ---------- TLS / Reality ----------

    security = q.get("security", "none")

    if security in ("tls", "reality"):
        tls = {
            "enabled": True,
        }

        if sni := q.get("sni"):
            tls["server_name"] = sni

        # uTLS fingerprint, например chrome/firefox
        if fp := q.get("fp"):
            tls["utls"] = {
                "enabled": True,
                "fingerprint": fp,
            }

        if alpn := q.get("alpn"):
            tls["alpn"] = alpn.split(",")

        if security == "reality":
            public_key = q.get("pbk")

            if not public_key:
                raise ValueError("Для Reality требуется параметр pbk")

            tls["reality"] = {
                "enabled": True,
                "public_key": public_key,
            }

            if sid := q.get("sid"):
                tls["reality"]["short_id"] = sid

        outbound["tls"] = tls

    elif security != "none":
        raise ValueError(f"Неизвестный security={security!r}")

    # ---------- Transport ----------

    transport_type = q.get("type", "tcp")

    # Для обычного TCP transport вообще не указываем.
    if transport_type == "ws":
        transport = {
            "type": "ws",
            "path": q.get("path", "/"),
        }

        if ws_host := q.get("host"):
            transport["headers"] = {
                "Host": ws_host,
            }

        outbound["transport"] = transport

    elif transport_type == "grpc":
        outbound["transport"] = {
            "type": "grpc",
            "service_name": q.get("serviceName", ""),
        }

    elif transport_type != "tcp":
        raise NotImplementedError(
            f"Transport {transport_type!r} пока не реализован")

    return outbound


def vless_hysteria2(uri: str) -> dict:
    """Преобразует Hysteria2-ссылку в outbound для sing-box."""

    u = urlsplit(uri)

    if u.scheme not in ("hysteria2", "hy2"):
        raise ValueError("Ожидался hysteria2:// или hy2://")

    q = {key: values[0] for key, values in parse_qs(u.query).items()}

    outbound = {
        "type": "hysteria2",
        "tag": "proxy",
        "server": u.hostname,
        "server_port": u.port or 443,
        "password": unquote(u.username or ""),
        "tls": {
            "enabled": True,
        },
    }

    if sni := q.get("sni"):
        outbound["tls"]["server_name"] = sni

    if q.get("insecure") == "1":
        outbound["tls"]["insecure"] = True

    if obfs_type := q.get("obfs"):
        outbound["obfs"] = {"type": obfs_type,
                            "password": q.get("obfs-password", "")}

    return outbound

def vmess_extractor(uri: str) -> dict:
    if not uri.startswith("vmess://"):
        raise ValueError("Ожидался vmess:// URI")

    # Стандартный формат v2rayN:
    # vmess://BASE64(JSON)
    encoded = uri[len("vmess://"):].split("#", 1)[0]
    encoded = unquote(encoded)

    # base64 часто приходит без '=' в конце
    encoded += "=" * (-len(encoded) % 4)

    try:
        raw = base64.urlsafe_b64decode(encoded).decode("utf-8")
        cfg = json.loads(raw)
    except Exception as e:
        raise ValueError("Некорректный VMess URI") from e

    host = cfg.get("add")
    uuid = cfg.get("id")

    try:
        port = int(cfg.get("port"))
        alter_id = int(cfg.get("aid", 0))
    except (TypeError, ValueError) as e:
        raise ValueError("Некорректные port/aid в VMess URI") from e

    if not host or not uuid or not port:
        raise ValueError(
            "В VMess URI отсутствуют add, port или id"
        )

    outbound = {
        "type": "vmess",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "uuid": uuid,
        "security": cfg.get("scy")
                    or cfg.get("security")
                    or "auto",
        "alter_id": alter_id,
    }

    # ---------- TLS ----------

    if cfg.get("tls") == "tls":
        tls = {
            "enabled": True
        }

        if sni := cfg.get("sni"):
            tls["server_name"] = sni

        if fp := cfg.get("fp"):
            tls["utls"] = {
                "enabled": True,
                "fingerprint": fp,
            }

        if alpn := cfg.get("alpn"):
            tls["alpn"] = [
                x for x in alpn.split(",") if x
            ]

        if str(cfg.get("insecure", "0")).lower() in ("1", "true"):
            tls["insecure"] = True

        outbound["tls"] = tls

    # ---------- Transport ----------

    transport_type = cfg.get("net", "tcp")
    path = cfg.get("path", "/")
    host_header = cfg.get("host", "")
    header_type = cfg.get("type", "none")

    # plain TCP transport в sing-box не указывается
    if transport_type == "tcp":
        # Старый VMess может иметь TCP + HTTP header.
        # В sing-box HTTP вынесен в отдельный transport.
        if header_type == "http":
            transport = {
                "type": "http",
                "path": path or "/",
            }

            if host_header:
                transport["host"] = [
                    x for x in host_header.split(",") if x
                ]

            outbound["transport"] = transport

        elif header_type not in ("", "none"):
            raise NotImplementedError(
                f"VMess TCP header {header_type!r} пока не реализован"
            )

    elif transport_type == "ws":
        transport = {
            "type": "ws",
            "path": path or "/",
        }

        if host_header:
            transport["headers"] = {
                "Host": host_header
            }

        outbound["transport"] = transport

    elif transport_type == "grpc":
        outbound["transport"] = {
            "type": "grpc",
            "service_name": path or "",
        }

    elif transport_type in ("h2", "http"):
        transport = {
            "type": "http",
            "path": path or "/",
        }

        if host_header:
            transport["host"] = [
                x for x in host_header.split(",") if x
            ]

        outbound["transport"] = transport

    elif transport_type == "quic":
        outbound["transport"] = {
            "type": "quic"
        }

    elif transport_type == "httpupgrade":
        transport = {
            "type": "httpupgrade",
            "path": path or "/",
        }

        if host_header:
            transport["host"] = host_header

        outbound["transport"] = transport

    else:
        raise NotImplementedError(
            f"VMess transport {transport_type!r} пока не реализован"
        )

    return outbound


def trojan_extractor(uri: str) -> dict:
    u = urlsplit(uri)

    if u.scheme != "trojan":
        raise ValueError("Ожидался trojan:// URI")

    host = u.hostname
    port = u.port

    # Берём всю userinfo-часть как пароль.
    if "@" not in u.netloc:
        raise ValueError("В Trojan URI отсутствует password")

    password = unquote(
        u.netloc.rsplit("@", 1)[0]
    )

    if not password or not host or not port:
        raise ValueError(
            "В Trojan URI отсутствуют password, host или port"
        )

    q = {
        key: values[0]
        for key, values in parse_qs(u.query).items()
    }

    outbound = {
        "type": "trojan",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "password": password,
    }

    # ---------- TLS / Reality ----------

    security = q.get("security", "tls")

    if security in ("tls", "reality"):
        tls = {
            "enabled": True
        }

        if sni := q.get("sni"):
            tls["server_name"] = sni

        if fp := q.get("fp"):
            tls["utls"] = {
                "enabled": True,
                "fingerprint": fp,
            }

        if alpn := q.get("alpn"):
            tls["alpn"] = [
                x for x in alpn.split(",") if x
            ]

        if q.get("insecure") in ("1", "true", "True"):
            tls["insecure"] = True

        if security == "reality":
            public_key = q.get("pbk")

            if not public_key:
                raise ValueError(
                    "Для Trojan Reality требуется pbk"
                )

            tls["reality"] = {
                "enabled": True,
                "public_key": public_key,
            }

            if sid := q.get("sid"):
                tls["reality"]["short_id"] = sid

        outbound["tls"] = tls

    elif security != "none":
        raise ValueError(
            f"Неизвестный security={security!r}"
        )

    # ---------- Transport ----------

    transport_type = q.get("type", "tcp")

    if transport_type == "tcp":
        pass

    elif transport_type == "ws":
        transport = {
            "type": "ws",
            "path": q.get("path", "/"),
        }

        if host_header := q.get("host"):
            transport["headers"] = {
                "Host": host_header
            }

        outbound["transport"] = transport

    elif transport_type == "grpc":
        outbound["transport"] = {
            "type": "grpc",
            "service_name": q.get("serviceName", ""),
        }

    elif transport_type in ("http", "h2"):
        transport = {
            "type": "http",
            "path": q.get("path", "/"),
        }

        if host_header := q.get("host"):
            transport["host"] = [
                x for x in host_header.split(",") if x
            ]

        outbound["transport"] = transport

    elif transport_type == "quic":
        outbound["transport"] = {
            "type": "quic"
        }

    elif transport_type == "httpupgrade":
        transport = {
            "type": "httpupgrade",
            "path": q.get("path", "/"),
        }

        if host_header := q.get("host"):
            transport["host"] = host_header

        outbound["transport"] = transport

    else:
        raise NotImplementedError(
            f"Trojan transport {transport_type!r} пока не реализован"
        )

    return outbound


def shadowsocks_extractor(uri: str) -> dict:
    if not uri.startswith("ss://"):
        raise ValueError("Ожидался ss:// URI")

    def decode_base64(value: str) -> str:
        value = unquote(value)
        value += "=" * (-len(value) % 4)

        try:
            return base64.urlsafe_b64decode(value).decode("utf-8")
        except Exception as e:
            raise ValueError(
                "Некорректная Base64-строка в Shadowsocks URI"
            ) from e

    def parse_host_port(value: str):
        # urlsplit умеет корректно разобрать hostname:port,
        # включая IPv6 в квадратных скобках.
        parsed = urlsplit("//" + value)

        host = parsed.hostname
        port = parsed.port

        if not host or not port:
            raise ValueError(
                "В Shadowsocks URI отсутствуют host или port"
            )

        return host, port

    body = uri[len("ss://"):]

    # Убираем fragment (#name)
    body = body.split("#", 1)[0]

    # ---------------- SIP002 ----------------
    #
    # ss://BASE64(method:password)@host:port
    # ss://method:password@host:port
    #
    if "@" in body:
        authority, _, query = body.partition("?")

        userinfo, host_port = authority.rsplit("@", 1)

        # Возможен завершающий /
        host_port = host_port.rstrip("/")

        host, port = parse_host_port(host_port)

        decoded_userinfo = unquote(userinfo)

        # Plain form:
        # method:password
        if ":" in decoded_userinfo:
            method, password = decoded_userinfo.split(":", 1)

            method = unquote(method)
            password = unquote(password)

        # Base64 form:
        # BASE64(method:password)
        else:
            decoded_userinfo = decode_base64(userinfo)

            if ":" not in decoded_userinfo:
                raise ValueError(
                    "В Shadowsocks userinfo отсутствует method:password"
                )

            method, password = decoded_userinfo.split(":", 1)

        q = parse_qs(query)

    # ---------------- Legacy ----------------
    #
    # ss://BASE64(method:password@host:port)
    #
    else:
        encoded, _, query = body.partition("?")

        decoded = decode_base64(encoded.rstrip("/"))

        if "@" not in decoded:
            raise ValueError(
                "Некорректный legacy Shadowsocks URI"
            )

        method_password, host_port = decoded.rsplit("@", 1)

        if ":" not in method_password:
            raise ValueError(
                "В Shadowsocks URI отсутствует method:password"
            )

        method, password = method_password.split(":", 1)

        host, port = parse_host_port(host_port)

        q = parse_qs(query)

    if not method or not password:
        raise ValueError(
            "В Shadowsocks URI отсутствуют method или password"
        )

    outbound = {
        "type": "shadowsocks",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "method": method,
        "password": password,
    }

    # ---------- SIP003 plugin ----------

    if plugin_values := q.get("plugin"):
        plugin_string = unquote(plugin_values[0])

        parts = plugin_string.split(";")

        plugin_name = parts[0]

        if plugin_name:
            outbound["plugin"] = plugin_name

        if len(parts) > 1:
            outbound["plugin_opts"] = ";".join(parts[1:])

    return outbound


config_extractor = {
    "vless": vless_extractor,

    "vmess": vmess_extractor,

    "trojan": trojan_extractor,
    
    "ss": shadowsocks_extractor,

    "hysteria2": vless_hysteria2,
    "hy2": vless_hysteria2,
}
vpn_link_pattern = "^([a-z][a-z0-9]*):"

def update_proxy(port: int):
    return {
        "http": f"socks5h://127.0.0.1:{port}",
        "https": f"socks5h://127.0.0.1:{port}",
    }

proxies = update_proxy(SOCKS_PORT)


# Ожидание запуска sing-box

def is_port_in_use(port: int, host: str = '127.0.0.1') -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            s.listen(1)
            return False  # Порт свободен
        except OSError:
            return True   # Порт занят
          
def get_free_tcp_port():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(('', 0))
    addr, port = tcp.getsockname()
    tcp.close()
    return port

def wait_for_port(port: int, process: subprocess.Popen, timeout=10):
    """Ожидает открытия SOCKS-порта, проверяя состояние процесса."""

    deadline = time.time() + timeout

    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"sing-box завершился с кодом {process.returncode}")

        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)

    raise TimeoutError("sing-box не поднял SOCKS-порт")


# Общее состояние

vpn_configs = []
used_vpn_links = FileStorageSet(used_vpn_links_filename)
last_configs_update = time.time() - vpn_configs_update_pause
target_person_id = 0
target_person_key = 0
success_vote = 0


# Загрузка и обновление VPN-ссылок


def update_configs_attempt():
    """Загружает VPN-ссылки из подписок за одну попытку."""

    global vpn_link_pattern

    extracted_vpn_configs = []
    for vpn_link in vpn_links:
        print("Process link: ", end="")
        print_with_color(f"{vpn_link}", color=Fore.YELLOW)
        try:
            r = orequests.get(vpn_link, timeout=15)

            r.raise_for_status()

            print_with_color("Succesfully load VPN links", color=Fore.GREEN)

            for line in r.text.splitlines():
                line = line.strip()

                if re.match(vpn_link_pattern, line):
                    extracted_vpn_configs.append(line)

        except orequests.RequestException as e:
            print("Extract links failed: ", end="")
            print_with_color(f"{e}", color=Fore.RED)

    return extracted_vpn_configs


def update_configs():
    """Пополняет очередь неиспользованными VPN-ссылками."""

    global vpn_configs
    global vpn_configs_update_pause
    global last_configs_update

    while len(vpn_configs) == 0:
        print_with_color("Обновляю конфиги VPN...", color=Fore.MAGENTA)
        time_passed_from_last_update = time.time() - last_configs_update
        if time_passed_from_last_update < vpn_configs_update_pause:
            left_time = vpn_configs_update_pause - time_passed_from_last_update
            print(
                f"Недавно обновлял. Подожду {int(left_time)} секунд до следующей попытки."
            )
            time.sleep(left_time)
            last_configs_update = time.time()

        extracted_vpn_configs = update_configs_attempt()

        vpn_configs = list(
            dict.fromkeys(
                link
                for link in extracted_vpn_configs
                if link not in used_vpn_links.storage
            )
        )

        if len(vpn_configs) > 0:
            last_configs_update = time.time()
            print("VPN конфиги обновлены!")
            print("==================================================")
            break

        print(
            f"Выгруженные VPN конфиги уже использовались. Подожду ещё {int(vpn_configs_update_pause / 60)} минут."
        )
        print(
            f'  P.S. Если это сообщение часто появляется, то либо увеличьте параметр "vpn_configs_update_pause", либо добавьте ещё подписок в "vpn_list_links"'
        )
        time.sleep(vpn_configs_update_pause)


# Поиск участников и голосование


def find_vote_candidates(page):
    """Находит целевого участника и допустимых альтернативных кандидатов."""

    soup = BeautifulSoup(page.text, "lxml")

    items = soup.find_all("div", class_="item")

    available_persons = []
    target_person_id = 0
    target_person_key = ""

    window_size = shutil.get_terminal_size((20, 20))

    status_bar = StatusBar(window_size.columns, max(len(items), 1))

    def status_print(*args):
        nonlocal status_bar
        status_bar.print(*args)

    for item in items:
        # Сохраняем текущую задержку при просмотре участников.
        time.sleep(0.01)
        status_bar.value = status_bar.value + 1

        person_id = item.get("data-id")
        person_key = item.get("data-key")

        name_tag = item.select_one('div.data > div.name > a[itemprop="name"]')

        place_tag = item.select_one("div.data > div.place")

        if name_tag is None or place_tag is None:
            continue

        name = name_tag.get_text(strip=True)
        place = place_tag.get_text(strip=True)

        # Для избавления от рисков изменения id, а тем более key кандидата
        if name in target_person_name:
            target_person_id = person_id
            target_person_key = person_key
            status_print(f"Целевой кандидат найден")
            continue

        if place not in ["Russia, Saint Petersburg", "Россия, Санкт-Петербург"]:
            available_persons.append({"id": person_id, "key": person_key})

    return target_person_id, target_person_key, available_persons


def core_algorithm() -> bool:
    """Загружает страницу и выполняет текущий алгоритм голосования."""

    global proxies
    global success_vote
    global max_successful_vote
    for browser in ["chrome", "firefox", "safari", "edge"]:
        if success_vote >= max_successful_vote:
            print("Максимальное количество голосований было достигнуто.")
            print(
                '  P.S. Если за один запуск программы нужно другое кол-во голосов, то поменяйте в конфиге "max_successful_vote"'
            )
            return False

        vpn_works = False
        try:
            session = requests.Session(
                impersonate=browser, base_url="https://www.missoffice.org", retry=1
            )

            print(f'Загружаю страницу... Успешных попыток: {success_vote}')

            page = session.get(
                "/contestants/2026/",
                headers={
                    "Accept-Language": "en-US,en;q=0.9",
                },
                proxies=proxies,
                timeout=vpn_check_timeout,
            )

            page.raise_for_status()

            print(
                "Загружена страница. Ищу целевую персону и выбираю альтернативных допустимых кандидатов..."
            )
            
            vpn_works = True

            time_for_vote_start = time.time()
            time_for_vote_end = time_for_vote_start + time_for_vote

            target_person_id, target_person_key, available_persons = (
                find_vote_candidates(page)
            )

            if target_person_id == 0:
                print_with_color(
                    f"{target_person_name[0]} не найден(а) в списке участников. Проверьте config.json на опечатки в имени.",
                    color=Fore.YELLOW,
                )
                print(
                    "При игнорировании данного сообщения поиск продолжится по указанному имени."
                )
                time.sleep(3)
                continue

            if len(available_persons) < 2:
                print_with_color(
                    "Подходящие альтернативные два участника для голосования не найдены. Проверьте условие фильтрации либо целевую страницу для голосования.",
                    color=Fore.RED,
                )
                continue

            second_person, third_person = random.sample(available_persons, 2)

            vote_persons = [
                {"id": target_person_id, "key": target_person_key},
                second_person,
                third_person,
            ]

            random.shuffle(vote_persons)

            if time.time() < time_for_vote_end:
                awaiting = time_for_vote_end - time.time()
                print(
                    f"Запрос готов. Ожидание перед отправкой: {int(awaiting)} секунд")
                time.sleep(awaiting)
            
            r = session.post(
                "/local/templates/adaptive/components/bitrix/news/contestants/bitrix/news.list/vote.v2/ajax.php",
                data=[
                    ("action", "vote"),
                    ("sl", "EN"),
                    ("id[]", f"{vote_persons[0]['id']}"),
                    ("id[]", f"{vote_persons[1]['id']}"),
                    ("id[]", f"{vote_persons[2]['id']}"),
                    ("key[]", f"{vote_persons[0]['key']}"),
                    ("key[]", f"{vote_persons[1]['key']}"),
                    ("key[]", f"{vote_persons[2]['key']}"),
                ],
                headers={
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Origin": "https://www.missoffice.org",
                    "Referer": "https://www.missoffice.org/contestants/2026/",
                    "X-Requested-With": "XMLHttpRequest",
                },
                proxies=proxies,
                timeout=15,
            )
            r.raise_for_status()

            print("Проголосовал.")

            response_data = r.json()

            if response_data.get("status", 0) == 1:
                success_vote = success_vote + 1
                print_with_color(
                    "Success", color=Fore.GREEN, brightness=Style.BRIGHT, end=""
                )
                print(f". Counter: {success_vote}")
            else:
                print_with_color(
                    "Failed", color=Fore.RED, brightness=Style.BRIGHT, end=""
                )
                print(": ", response_data)
        except Exception as e:
            print(f"Exception: {e}")
        finally:
            if vpn_works and pause_between_vote:
                print(f"Пауза между голосованиями ({pause_between_vote=})")
                time.sleep(pause_between_vote)
        if not vpn_works:
            return True
    return True


# Основной цикл: выбор VPN, запуск sing-box и голосование

def main():
    while True:
        update_configs()

        print("Выбираю новую ссылку")
        vpn_link = vpn_configs.pop(0)
        print('==========================================')
        # used_vpn_links.add(vpn_link)

        print_with_color(f"{vpn_link}", Fore.CYAN, brightness=Style.BRIGHT)

        vpn_protocol = urlsplit(vpn_link)
        config = ""
        if vpn_protocol.scheme in config_extractor.keys():
            try:
                config = config_extractor[vpn_protocol.scheme](vpn_link)
            except Exception as e:
                print(f"Extracting config from link error: {e}")
                used_vpn_links.add(vpn_link)
                continue
        else:
            print(f'VPN protocol "{vpn_protocol.scheme}" is unsupported')
            used_vpn_links.add(vpn_link)
            continue

        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "sing-box.json"

            choosen_port = SOCKS_PORT
            
            if is_port_in_use(choosen_port):
                print_with_color(f'Стандартный порт {choosen_port} уже занят.', color=Fore.RED)
                print('Выключите программу занимающую порт!')
                print_with_color('Ищу свободный порт...', color=Fore.CYAN, brightness=Style.DIM)
                
                while True:
                    try:
                        choosen_port = get_free_tcp_port()
                        
                        if not is_port_in_use(choosen_port):
                            print_with_color(f'Найден новый порт: {choosen_port}', color=Fore.YELLOW)
                            break
                        
                    except Exception as e:
                        print_with_color('FATAL! Ошибка поиска свободного порта: ', color=Fore.RED, end="")
                        print(f'{e}')
                        print('Выключите ненужные программы занимающие все оставшиеся порты.')
                        print_with_color('Заново ищу свободный порт...', color=Fore.CYAN)
                

            config_path.write_text(
                json.dumps(make_config(config, choosen_port), indent=2), encoding="utf-8"
            )

            # Можно сначала проверить сгенерированный конфиг
            check_run_result = subprocess.run(
                ["sing-box", "check", "-c", str(config_path)],
            )

            if check_run_result.returncode != 0:
                print(
                    f"FatalError: config created with vpn_link ({vpn_link}) was created wrongly. Skip"
                )
                continue
              
            if is_port_in_use(choosen_port):
                print_with_color(f'Выбранный порт {choosen_port} заняли во время создания vpn конфиг файла.')
                vpn_configs.insert(0, vpn_link)
                print('VPN ссылка возвращена на повторную обработку.')
                continue

            process = subprocess.Popen(["sing-box", "run", "-c", str(config_path)])

            try:
                wait_for_port(choosen_port, process)
                print("VPN запущен.")
                proxies = update_proxy(choosen_port)

                result = core_algorithm()

                if not result:
                    break
                
                used_vpn_links.add(vpn_link)

                print("=========================================")
            finally:
                process.terminate()

                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()

def format_time_diff(diff: float):
    result = ""

    val = diff * 1000

    result = f'{int(val % 1000):0>3d}'
    val = val // 1000
    
    result = f'{int(val % 60):0>2d}.{result}'
    val = val // 60
    
    result = f'{int(val % 60):0>2d}:{result}'
    val = val // 60
    
    result = f'{int(val)}:{result}'
    
    return result
  
main_start_time = time.time()
main()
main_end_time = time.time()
spend_time = main_end_time - main_start_time

print(f'Время работы: {format_time_diff(spend_time)}\n')

