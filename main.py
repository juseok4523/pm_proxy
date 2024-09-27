import time, sys
import platform
import subprocess
import ctypes
from pathlib import Path
import asyncio
from queue import Queue

from mitmproxy import http
from threading import Thread, Event
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster
from mitmproxy import ctx

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 7090
FILTER_PORT = 8244 # change port

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_mitmproxy_cert_path():
    possible_paths = [
        Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem",  
        Path.cwd() / "mitmproxy-ca-cert.pem"
    ]

    for path in possible_paths:
        if path.exists():
            return path
    return None

def install_mitmproxy_cert(cert_path):
    system = platform.system()

    print(f"{system}에서 인증서 설치를 진행합니다.")

    if system == "Windows":
        result = subprocess.run(
            ["certutil", "-verifystore", "Root", "mitmproxy"],
            capture_output=True, text=True
        )
        if "mitmproxy" not in result.stdout:
            try:
                print(str(cert_path))
                subprocess.run(["certutil" "-addstore", "Root", str(cert_path)], check=True)
                print("Mitmproxy 인증서가 Windows 신뢰 저장소에 설치되었습니다.")
                
            except Exception as e:
                dirname = cert_path.parent
                cert_path = "mitmproxy-ca-cert.cer"
                print(f"인증서 설치 중 오류 발생: {e}")
                print(f"자동으로 인증서 설치가 안될 시, 수동으로 인증서를 설치해주세요. 설치 방법은 다음과 같습니다.")
                print(f"1.{dirname}에 접근합니다.")
                print(f"2.{cert_path}를 더블클릭하여 실행합니다.")
                print(f"3.팝업창 하단의 [인증서 설치]를 클릭하고, 그 다음 팝업창에서도 [다음] - [다음] - [마침]을 클릭해줍니다.")
                print(f"4.이제 프로그램을 다시 실행해주세요")
                sys.exit(0)
        else:
            print(f"Mitmproxy 인증서가 정상적으로 설치되어 있습니다.")

def set_windows_proxy(enable, server):
    import winreg as reg
    try:
        internet_settings = reg.OpenKey(reg.HKEY_CURRENT_USER,
                                        r'Software\Microsoft\Windows\CurrentVersion\Internet Settings',
                                        0, reg.KEY_ALL_ACCESS)
        reg.SetValueEx(internet_settings, 'ProxyEnable', 0, reg.REG_DWORD, enable)
        reg.SetValueEx(internet_settings, 'ProxyServer', 0, reg.REG_SZ, server)
        # os.system("RUNDLL32.EXE inetcpl.cpl,LaunchConnectionDialog")
    except Exception as e:
        print(f"Failed to set Windows proxy: {e}")

class ProxyAddon(object):
    def __init__(self, q, filter_cli_port=None):
        self.queue = q
        self.filter_cli_port = filter_cli_port
    
    def request(self, flow: http.HTTPFlow) -> None:
        request = flow.request
        client_port = flow.client_conn.peername[1]
        if self.filter_cli_port is not None and self.filter_cli_port == client_port:
            msg = f"[Filter] Captured Request: {request.method} {request.url}"
        else :
            msg = f"Captured Request: {request.method} {request.url}"
        self.queue.put(msg)

class myMitmproxy():
    def __init__(self):
        self.queue = Queue()
    
    def start_loop(self,loop):
        asyncio.set_event_loop(loop)
        loop.run_forever()

    async def stop_loop(self):
        loop = asyncio.get_event_loop()
        loop.stop()
        loop.close()
    
    def start_proxy(self):
        new_loop = asyncio.new_event_loop()
        self.thread = Thread(target=self.start_loop, daemon=True, args=(new_loop,))
        self.thread.start()
        self.future = asyncio.run_coroutine_threadsafe(self.start_mitmproxy(), new_loop)
        return new_loop
    
    def stop_proxy(self, loop):
        try:
            asyncio.run_coroutine_threadsafe(self.stop_loop(), loop)
            self.future.cancel()
            self.thread.join()
        except BaseException:
            pass
    
    def run_proxy(self):
        asyncio.run(self.start_mitmproxy())
        
    async def start_mitmproxy(self):
        options = Options(listen_host=PROXY_HOST, listen_port=PROXY_PORT)
        self.master = DumpMaster(options)
        self.master.addons.add(ProxyAddon(self.queue))
        ctx.options.flow_detail = 0
        try:
            await self.master.run()
        except Exception as e:
            print(e)
            self.master.shutdown()
        
    def print_queue(self):
        return self.queue.queue

def main():
    cert_path = get_mitmproxy_cert_path()
    if cert_path is None:
        print("Mitmproxy 인증서가 생성되지 않았습니다. mitmproxy를 먼저 실행하여 인증서를 생성하세요.")
    else:
        install_mitmproxy_cert(cert_path)
    set_windows_proxy(1, f'{PROXY_HOST}:{PROXY_PORT}')
    proxy = myMitmproxy()
    try:
        print("프로그램이 작동 중입니다. ...을 켜서 다운로드하고자 하는 영상을 재생해주세요. \n재생되었다면(영상이 끝까지 실행되지 않아도 괜찮습니다. 정상적으로 재생되기만 하면 됩니다.) 키보드에서 Ctrl+C를 눌러주세요.")
        loop = proxy.start_proxy()
        time.sleep(3600)
    except KeyboardInterrupt:
        proxy.stop_proxy(loop)
    finally:
        set_windows_proxy(0, '')
        print(proxy.print_queue())
    
if __name__ == "__main__":
    main()