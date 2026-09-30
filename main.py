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


class FileStorageSet:
    """Хранит уникальные строки и записывает новые значения в файл."""

    def __init__(self, filename: str):
        self.__storage = set()

        try:
            self.__file = open(filename, "r")

            for line in self.__file.readlines():
                line = line.strip()
                if line:
                    self.__storage.add(line)

            self.__file.close()
        except FileNotFoundError:
            pass

        self.__file = open(filename, "a")

    def add(self, line: str):
        if line in self.__storage:
            return

        self.__storage.add(line)
        self.__file.write(f"{line}\n")
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
        self.__width = width
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

SOCKS_PORT = 10808
disable_sing_box_log = poller_config["disable_sing_box_log"]
vpn_links = poller_config["vpn_list_links"]
vpn_configs_update_pause = int(
    poller_config.get("vpn_configs_update_pause", 15)) * 60
time_for_vote = int(poller_config.get("time_for_vote", 15))
target_person_name = poller_config["target_person_name"]
max_successful_vote = poller_config["max_successful_vote"]
pause_between_vote = poller_config["pause_between_vote"]


# Конфигурация sing-box и разбор VPN-ссылок


def make_config(outbound: dict) -> dict:
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
                "listen_port": SOCKS_PORT,
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


config_extractor = {
    "vless": vless_extractor,
    "hysteria2": vless_hysteria2,
    "hy2": vless_hysteria2,
}
vpn_link_pattern = "^([a-z][a-z0-9]*):"

proxies = {
    "http": f"socks5h://127.0.0.1:{SOCKS_PORT}",
    "https": f"socks5h://127.0.0.1:{SOCKS_PORT}",
}


# Ожидание запуска sing-box


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

    status_bar = StatusBar(20, max(len(items), 1))

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
    for browser in ["chrome", "firefox", "safari"]:
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

            page = session.get(
                "/contestants/2026/",
                headers={
                    "Accept-Language": "en-US,en;q=0.9",
                },
                proxies=proxies,
                timeout=10,
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
            if not vpn_works:
              return True
            if pause_between_vote:
                print(f"Пауза между голосованиями ({pause_between_vote=})")
                time.sleep(pause_between_vote)
    return True


# Основной цикл: выбор VPN, запуск sing-box и голосование

while True:
    update_configs()

    print("Выбираю новую ссылку")
    vpn_link = vpn_configs.pop(0)
    print('==========================================')
    # used_vpn_links.add(vpn_link)

    print_with_color(f"{vpn_link}", Fore.CYAN)

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

        config_path.write_text(
            json.dumps(make_config(config), indent=2), encoding="utf-8"
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

        process = subprocess.Popen(["sing-box", "run", "-c", str(config_path)])

        try:
            wait_for_port(SOCKS_PORT, process)
            print("VPN запущен.")

            result = core_algorithm()
            used_vpn_links.add(vpn_link)

            if not result:
                break

            print("=========================================")
        finally:
            process.terminate()

            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
