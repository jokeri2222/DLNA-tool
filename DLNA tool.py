import subprocess
import sys
import pkg_resources
import os

requirements_path = os.path.join(os.path.dirname(__file__), "requirements.txt")

if os.path.exists(requirements_path):
    with open(requirements_path) as f:
        required = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    installed = {pkg.key for pkg in pkg_resources.working_set}
    missing = []

    for req in required:
        try:
            pkg_name = pkg_resources.Requirement.parse(req).key
            if pkg_name not in installed:
                missing.append(req)
        except Exception:
            print(f"[WARNING] Skipping malformed requirement: {req}")

    if missing:
        print(f"[BOOTSTRAP] Installing missing packages: {missing}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])


import asyncio
import requests
from async_upnp_client.search import async_search
import tkinter as tk
from tkinter import ttk, Menu, filedialog
import xmltodict
import threading
from aiohttp import web
import socket
from async_upnp_client.aiohttp import AiohttpRequester
from async_upnp_client.client_factory import UpnpFactory
from ping3 import ping
import urllib.parse
import time
from hashlib import sha256
from yt_dlp import YoutubeDL
import aiohttp
from tkinter.simpledialog import askstring


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

# ---- File Server Class ----
class FileServer:
    def __init__(self, port=8000):
        self.port = port
        self.files = {}  # filename: path
        self.app = web.Application()
        self.app.router.add_get('/files/{filename}', self.handle_file_request)
        self.app.router.add_get('/youtube/{video_id}', self.youtube_proxy_handler)
        self.runner = None

    async def start(self):
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "0.0.0.0", self.port)
        await site.start()
        print(f"[FILE SERVER] Started at http://{get_local_ip()}:{self.port}/")

    def add_file(self, path):
        hashed = sha256(path.encode()).hexdigest()
        extension = os.path.splitext(path)[1]
        filename = f"{hashed}{extension}"
        self.files[filename] = path
        print(f"[FILE SERVER] Now serving: {path} at /files/{filename}")
        return filename

    async def handle_file_request(self, request):
        filename = request.match_info['filename']
        path = self.files.get(filename)
        if path and os.path.exists(path):
            return web.FileResponse(path)
        else:
            raise web.HTTPNotFound()

    @staticmethod
    async def youtube_proxy_handler(request):
        video_id = request.match_info['video_id']
        url = f"https://www.youtube.com/watch?v={video_id}"

        # Get direct video URL
        ydl_opts = {'quiet': True, 'format': 'best[ext=mp4]/best'}
        with YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=False)
            stream_url, title = info['url'], info['title']

        print(f"[FILE SERVER] Now serving: {title} at /youtube/{video_id}")

        # Stream it as a proxy
        async with aiohttp.ClientSession() as session:
            async with session.get(stream_url) as resp:
                headers = {k: v for k, v in resp.headers.items() if k.lower().startswith("content-")}
                return web.Response(body=await resp.read(), headers=headers)

    def url_for(self, filename):
        return f"http://{get_local_ip()}:{self.port}/files/{filename}?v={int(time.time())}"


file_server = FileServer(port=8000)

# ---- DLNA Commands ----
async def send_dlna_stream_command(device_url, media_url, loop_forever=True):
    requester = AiohttpRequester()
    factory = UpnpFactory(requester)
    device = await factory.async_create_device(device_url)
    av_transport = device.service("urn:schemas-upnp-org:service:AVTransport:1")

    async def play_video():
        await av_transport.action("SetAVTransportURI").async_call(
            InstanceID=0,
            CurrentURI=media_url,
            CurrentURIMetaData=""
        )
        await av_transport.action("Play").async_call(
            InstanceID=0,
            Speed="1"
        )

    await play_video()

    if loop_forever:
        async def loop_forever_task():
            while True:
                result = await av_transport.action("GetTransportInfo").async_call(InstanceID=0)
                if result["CurrentTransportState"] == "STOPPED":
                    print("[LOOP] Video ended, restarting...")
                    await play_video()

        task = asyncio.create_task(loop_forever_task())
        stream_tasks[device_url] = task


async def stop_dlna_stream_command(device_url):
    # Cancel the loop task if it's running
    task = stream_tasks.pop(device_url, None)
    if task:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            print(f"[LOOP] Streaming loop cancelled for {device_url}")

    requester = AiohttpRequester()
    factory = UpnpFactory(requester)
    device = await factory.async_create_device(device_url)
    av_transport = device.service("urn:schemas-upnp-org:service:AVTransport:1")

    await av_transport.action("Stop").async_call(InstanceID=0)

async def browse_media_server(device_url, object_id="0"):
    requester = AiohttpRequester()
    factory = UpnpFactory(requester)
    device = await factory.async_create_device(device_url)
    content_dir = device.service("urn:schemas-upnp-org:service:ContentDirectory:1")

    result = await content_dir.action("Browse").async_call(
        ObjectID=object_id,
        BrowseFlag="BrowseDirectChildren",
        Filter="*",
        StartingIndex=0,
        RequestedCount=1000,
        SortCriteria=""
    )

    items = xmltodict.parse(result["Result"])["DIDL-Lite"]
    return items.get("item", [])


# ---- Device Tracking and GUI ----
known_locations = set()
stream_tasks = {}
categorized_devices = {
    "Media Centers": [],
    "Screens": [],
    "Unknown devices": []
}

root = tk.Tk()
root.title("DLNA Device Controller")
frame = ttk.Frame(root)
tree = ttk.Treeview(frame, columns=["Device Name"])
tree.heading("#0", text="Device Name")
v_scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
tree.configure(yscrollcommand=v_scrollbar.set)
tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

category_nodes = {}
tree_items_to_devices = {}

def safe_insert_device(category, device_info):
    if category not in category_nodes:
        category_nodes[category] = tree.insert("", tk.END, text=category, open=True)
    item_id = tree.insert(category_nodes[category], tk.END, text=device_info["Name"])
    tree_items_to_devices[item_id] = device_info

def remove_device_from_gui(location):
    for item_id, device in list(tree_items_to_devices.items()):
        if device.get("Location") == location:
            tree.delete(item_id)
            del tree_items_to_devices[item_id]
            break
    for category in categorized_devices:
        categorized_devices[category] = [
            d for d in categorized_devices[category] if d.get("Location") != location
        ]
    known_locations.discard(location)

async def ping_devices_loop():
    while True:
        await asyncio.gather(*(check_device(location) for location in list(known_locations)))
        await asyncio.sleep(1)

async def check_device(location):
    ip = location.split("/")[2].split(":")[0]
    try:
        response = await asyncio.to_thread(ping, ip, timeout=30)
        if response is None:
            raise TimeoutError
    except Exception:
        print(f"Device at {location} unresponsive. Removing...")
        root.after(0, lambda: remove_device_from_gui(location))

def categorize_device(location, device_info):
    if location in known_locations:
        return
    known_locations.add(location)

    _type = device_info["Type"]
    if "MediaRenderer" in _type:
        category = "Screens"
    elif "MediaServer" in _type:
        category = "Media Centers"
    else:
        category = "Unknown devices"

    categorized_devices[category].append(device_info)
    root.after(0, lambda: safe_insert_device(category, device_info))

async def discover_loop():
    async def handle_device(response):
        device_info = {
            "USN": response.get("USN", "Unknown"),
            "ST": response.get("ST", "Unknown"),
            "Location": response.get("LOCATION", "Unknown"),
            "Name": response.get("MYNAME", "Unknown"),
            "Type": response.get("LOCATION", "Unknown")
        }

        try:
            response = requests.get(device_info["Location"], timeout=5)
            _xml = xmltodict.parse(response.content)
            device_info["Name"] = _xml["root"]["device"]["friendlyName"]
            device_info["Type"] = _xml["root"]["device"]["deviceType"]
        except Exception:
            pass

        categorize_device(device_info["Location"], device_info)

    print("Searching for UPnP/DLNA devices...")
    while True:
        await async_search(async_callback=handle_device, timeout=30)
        await asyncio.sleep(1)

def stream_file_to_device(device, filetypes, media_type):
    file_path = filedialog.askopenfilename(
        title=f"Select {media_type} File",
        filetypes=filetypes
    )
    if not file_path:
        return
    filename = os.path.basename(file_path)

    print(f"[STREAM {media_type.upper()}] Selected: {file_path}")

    async def stream():
        filename = file_server.add_file(file_path)
        media_url = file_server.url_for(filename)
        await send_dlna_stream_command(device["Location"], media_url)

    asyncio.run_coroutine_threadsafe(stream(), loop)

def stream_youtube_to_device(device):
    url = askstring("YouTube URL", "Enter the YouTube video URL:")
    if not url:
        return

    video_id = None
    try:
        parsed = urllib.parse.urlparse(url)
        if "youtu.be" in parsed.netloc:
            # Handle short youtu.be URLs
            video_id = parsed.path.strip("/")
        elif "youtube.com" in parsed.netloc:
            if "/watch" in parsed.path:
                video_id = urllib.parse.parse_qs(parsed.query)['v'][0]
            elif "/shorts/" in parsed.path:
                video_id = parsed.path.split("/shorts/")[1].split("/")[0]
    except Exception:
        pass

    if not video_id:
        print("[ERROR] Invalid or unsupported YouTube URL format.")
        return

    media_url = f"http://{get_local_ip()}:{file_server.port}/youtube/{video_id}"

    metadata = f"""
    <item xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/">
        <dc:title>YouTube Stream</dc:title>
        <upnp:class>object.item.videoItem</upnp:class>
        <res protocolInfo="http-get:*:video/mp4:*">{media_url}</res>
    </item>
    """

    async def stream():
        await send_dlna_stream_command(device["Location"], media_url, metadata)

    asyncio.run_coroutine_threadsafe(stream(), loop)


def stop_streaming(device):
    location = device.get("Location", "")
    asyncio.run_coroutine_threadsafe(stop_dlna_stream_command(location), loop)
    print(f"Stopped streaming on {device['Name']}")

def browse_and_show_media(device):
    async def browse_and_display():
        items = await browse_media_server(device["Location"])
        if not items:
            print(f"[MEDIA SERVER] No content found on {device['Name']}")
            return

        def show_window():
            win = tk.Toplevel(root)
            win.title(f"Files on {device['Name']}")
            listbox = tk.Listbox(win, width=80)
            listbox.pack(fill=tk.BOTH, expand=True)

            for item in items:
                title = item.get("dc:title", "Unknown Title")
                listbox.insert(tk.END, title)

        root.after(0, show_window)

    asyncio.run_coroutine_threadsafe(browse_and_display(), loop)



def show_context_menu(event):
    item_id = tree.identify_row(event.y)
    if not item_id or item_id not in tree_items_to_devices:
        return

    device = tree_items_to_devices[item_id]
    _type = device.get("Type", "")

    menu = Menu(root, tearoff=0)

    if "MediaServer" in _type:
        menu.add_command(
            label="Browse Files",
            command=lambda: browse_and_show_media(device)
        )

    if "MediaRenderer" in _type:
        menu.add_command(
            label="Stream Video",
            command=lambda: stream_file_to_device(
                device,
                [("Video Files", "*.mp4 *.avi *.mkv *.mov"), ("All Files", "*.*")],
                "video"
            )
        )
        menu.add_command(
            label="Stream Image",
            command=lambda: stream_file_to_device(
                device,
                [("Image Files", "*.jpg *.jpeg *.png *.bmp"), ("All Files", "*.*")],
                "image"
            )
        )
        menu.add_command(
            label="Stream YouTube Video",
            command=lambda: stream_youtube_to_device(device)
        )
        menu.add_command(
            label="Stop Streaming",
            command=lambda: stop_streaming(device)
        )

    menu.post(event.x_root, event.y_root)


tree.bind("<Button-3>", show_context_menu)

# ---- Asyncio Background Thread Setup ----
def start_async_loop(loop):
    asyncio.set_event_loop(loop)
    loop.run_until_complete(asyncio.gather(
        file_server.start(),
        discover_loop(),
        ping_devices_loop()
    ))

loop = asyncio.new_event_loop()
threading.Thread(target=start_async_loop, args=(loop,), daemon=True).start()

# ---- Launch GUI ----
root.mainloop()
