import json
import socket
import subprocess
import tempfile
import time
import re
import random
from pathlib import Path
from urllib.parse import urlsplit, parse_qs, unquote

import requests as orequests

from curl_cffi import requests
from bs4 import BeautifulSoup

with open("./config.json", "r", encoding="utf-8") as f:
    poller_config = json.load(f)

# Постоянные данные

SOCKS_PORT = 10808


def make_config(outbound: dict) -> dict:
    return {
        "log": {
            "level": "error",
            "timestamp": True
        },

        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": SOCKS_PORT
            }
        ],

        "outbounds": [
            outbound
        ],

        "route": {
            "final": "proxy"
        }
    }


def vless_extractor(uri: str) -> dict:
    u = urlsplit(uri)

    if u.scheme != "vless":
        raise ValueError("Ожидался vless:// URI")

    uuid = unquote(u.username or "")
    host = u.hostname
    port = u.port

    if not uuid or not host or not port:
        raise ValueError("В URI отсутствуют UUID, host или port")

    q = {
        key: values[0]
        for key, values in parse_qs(u.query).items()
    }

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
                raise ValueError(
                    "Для Reality требуется параметр pbk"
                )

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
            f"Transport {transport_type!r} пока не реализован"
        )

    return outbound


def vless_hysteria2(uri: str) -> dict:
    u = urlsplit(uri)

    if u.scheme not in ("hysteria2", "hy2"):
        raise ValueError("Ожидался hysteria2:// или hy2://")

    q = {
        key: values[0]
        for key, values in parse_qs(u.query).items()
    }

    outbound = {
        "type": "hysteria2",
        "tag": "proxy",
        "server": u.hostname,
        "server_port": u.port or 443,
        "password": unquote(u.username or ""),
        "tls": {
            "enabled": True,
        }
    }

    if sni := q.get("sni"):
        outbound["tls"]["server_name"] = sni

    if q.get("insecure") == "1":
        outbound["tls"]["insecure"] = True

    if obfs_type := q.get("obfs"):
        outbound["obfs"] = {
            "type": obfs_type,
            "password": q.get("obfs-password", "")
        }

    return outbound


config_extractor = {
    'vless': vless_extractor,
    'hysteria2': vless_hysteria2,
    'hy2': vless_hysteria2
}
vpn_link_pattern = "^([a-z][a-z0-9]*):"

proxies = {
    "http": f"socks5h://127.0.0.1:{SOCKS_PORT}",
    "https": f"socks5h://127.0.0.1:{SOCKS_PORT}",
}


def wait_for_port(port: int, process: subprocess.Popen, timeout=10):
    deadline = time.time() + timeout

    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"sing-box завершился с кодом {process.returncode}"
            )

        try:
            with socket.create_connection(
                ("127.0.0.1", port),
                timeout=0.2
            ):
                return
        except OSError:
            time.sleep(0.1)

    raise TimeoutError("sing-box не поднял SOCKS-порт")


# Общее состояние
vpn_links = poller_config['vpn_list_links']
vpn_configs = []
pause = int(poller_config.get("pause", 15)) * 60
used_vpn_links = set()
last_configs_update = time.time() - pause
target_person_name = poller_config['target_person_name']
target_person_id = 0
target_person_key = 0



def update_configs():
    def update_configs_attempt():
        global vpn_link_pattern

        extracted_vpn_configs = []
        for vpn_link in vpn_links:
            print(f'Process link: {vpn_link}')
            try:
                r = orequests.get(
                    vpn_link,
                    timeout=15
                )

                r.raise_for_status()

                for line in r.text.splitlines():
                    line = line.strip()

                    if re.match(vpn_link_pattern, line):
                        extracted_vpn_configs.append(line)

            except orequests.RequestException as e:
                print("Extract links failed:", e)

        return extracted_vpn_configs

    global vpn_configs
    global pause
    global last_configs_update

    while len(vpn_configs) == 0:
        time_passed_from_last_update = time.time() - last_configs_update
        if (time_passed_from_last_update < pause):
            left_time = pause - time_passed_from_last_update
            print(f"Sleep for {int(left_time)} sec until next attempt")
            time.sleep(left_time)
            last_configs_update = time.time()

        extracted_vpn_configs = update_configs_attempt()

        vpn_configs = [
            link for link in extracted_vpn_configs
            if link not in used_vpn_links
        ]

        if (len(vpn_configs) > 0):
            last_configs_update = int(time.time())
            break

        print(
            f'No vpn links were extracted from list of links. Sleep for {int(pause / 60)} minute(s)')
        time.sleep(pause)

# Основной алгоритм


def core_algorithmTest():

    global proxies
    try:
        result = requests.get(
            "https://example.com",
            # "https://demoqa.com/",
            proxies=proxies,
            impersonate="chrome",
            timeout=15
        )
        result.raise_for_status()

        print("VPN works")

        with open("hehe.html", "w") as file:
            file.write(result.text)
            print('Successful write')
    except Exception as e:
        print(f"Exception: {e}")


def core_algorithm():
    global proxies
    for browser in ["chrome", "firefox", "safari"]:
        try:
            session = requests.Session(impersonate=browser, base_url="https://www.missoffice.org")

            page = session.get(
                "/contestants/2026/",
                headers={
                    "Accept-Language":
                    "en-US,en;q=0.9",
                },
                proxies=proxies,
                timeout=15
            )

            page.raise_for_status()
            
            time.sleep(15)

            # taking elements

            soup = BeautifulSoup(page.text, "lxml")

            items = soup.find_all("div", class_="item")

            available_persons = []
            target_person_id = 0
            target_person_key = ""

            for item in items:
                person_id = item.get("data-id")
                person_key = item.get("data-key")
                
                name_tag = item.select_one(
                    'div.data > div.name > a[itemprop="name"]'
                )

                place_tag = item.select_one(
                    'div.data > div.place'
                )
                
                if name_tag is None or place_tag is None:
                    continue
                
                name = name_tag.get_text(strip=True)
                place = place_tag.get_text(strip=True)
                
                if (name in target_person_name):
                    target_person_id = person_id
                    target_person_key = person_key
                    print("Targer person was found")
                    continue
                
                if (place not in ["Russia, Saint Petersburg", "Россия, Санкт-Петербург"]):
                    available_persons.append({'id': person_id, 'key': person_key})
            
            if (target_person_id == 0):
                print("ERROR: Targer person was not found. Check config.json")
                continue
            
            if (len(available_persons) < 2):
                print("Alternative available persons must be at least 2")
                continue
            second_person, third_person = random.sample(available_persons, 2)
            
            vote_persons = [
              {
                'id' : target_person_id,
                'key' : target_person_key
              },
              second_person,
              third_person
            ]
            
            random.shuffle(vote_persons)

            r = session.post(
                "/local/templates/adaptive/components/bitrix/news/contestants/bitrix/news.list/vote.v2/ajax.php",
                # data={
                #     'action': "vote",
                #     'sl': 'EN',
                #     'id': [
                #         f'{vote_persons[0]['id']}',
                #         f'{vote_persons[1]['id']}',
                #         f'{vote_persons[2]['id']}',
                #     ],
                #     'key': [
                #         f'{vote_persons[0]['key']}',
                #         f'{vote_persons[1]['key']}',
                #         f'{vote_persons[2]['key']}',
                #     ]
                # },
                data=[
                  ("action", "vote"),
                  ("sl", "EN"),

                  ("id[]", f'{vote_persons[0]['id']}'),
                  ("id[]", f'{vote_persons[1]['id']}'),
                  ("id[]", f'{vote_persons[2]['id']}'),

                  ("key[]", f'{vote_persons[0]['key']}'),
                  ("key[]", f'{vote_persons[1]['key']}'),
                  ("key[]", f'{vote_persons[2]['key']}'),
                ],
                headers={
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "Accept-Language": "ru-GB,ru;q=0.9,en-US;q=0.8,en;q=0.7",
                    "Origin": "https://www.missoffice.org",
                    "Referer": "https://www.missoffice.org/contestants/2026/",
                    "X-Requested-With": "XMLHttpRequest",
                },
                proxies=proxies,
                timeout=15
            )
            r.raise_for_status()

            print("VPN works")

            response_data = r.json()

            if response_data.get("status", 0) == 1:
                print("Success")
            else:
                print("Failed:", response_data)
        except Exception as e:
            print(f"Exception: {e}")
        finally:
            time.sleep(10)


# coun = 0
# while coun == 0:
#     coun = 1
#     vpn_link = "hysteria2://kpiPdhtD5u@5.252.224.78:4443?security=tls&alpn=h3&fp=firefox#nc-hysteria2-udp-4"
while True:
    update_configs()

    print('Take first element')
    vpn_link = vpn_configs.pop(0)
    used_vpn_links.add(vpn_link)

    print(f'{vpn_link=}')

    vpn_protocol = urlsplit(vpn_link)
    config = ""
    if vpn_protocol.scheme in config_extractor.keys():
        try:
            config = config_extractor[vpn_protocol.scheme](vpn_link)
        except Exception as e:
            print(f"Extracting config from link error: {e}")
            continue
    else:
        print(f'VPN protocol "{vpn_protocol.scheme}" is unsupported')
        continue

    with tempfile.TemporaryDirectory() as tmp:
        config_path = Path(tmp) / "sing-box.json"

        config_path.write_text(
            json.dumps(make_config(config), indent=2),
            encoding="utf-8"
        )

        # Можно сначала проверить сгенерированный конфиг
        check_run_result = subprocess.run(
            ["sing-box", "check", "-c", str(config_path)],
        )

        if (check_run_result.returncode != 0):
            print(
                f"FatalError: config created with vpn_link ({vpn_link}) was created wrongly. Skip")
            continue

        process = subprocess.Popen([
            "sing-box",
            "run",
            "-c",
            str(config_path)
        ])

        try:
            wait_for_port(SOCKS_PORT, process)

            core_algorithm()
        finally:
            process.terminate()

            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
