import json
import hashlib
import base64
import glob
import requests
import os
import re
import m3u8
import shutil
from Crypto.Cipher import AES
import threading
import uuid
import concurrent.futures

headers = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,ja;q=0.7",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "Pragma": "no-cache",
    "Referer": "http://vip.fjzsbks.com/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "authorization": "eyJhbGciOiJIUzI1NiJ9.eyJ1bmlvbklkIjoiMTcwNTcxNjQwNjIwNCIsImxvZ2luSXAiOiI1OS42MS4xNjguMTQ0IiwicG9ydGFsSWQiOiIyNTM3NDAiLCJwbGF0Zm9ybSI6ImpvaW5lYXN0LWFwcCIsInN1YiI6ImpvaW5lYXN0IiwianRpIjoiZjIxMjhhMDctNWQ3OS00ZmIwLWI3MjQtMTE1MmMzZTMxMjc0IiwiaWF0IjoxNzA1NzE2NDA2LCJleHAiOjE3MTA5MDA0MDZ9.2cMa7KjbYc5pSnhnY3x0igfNMDRS8hopjJbsiGlruIU",
    "joineast-request-path": "/playerVideo/141",
    "joineast-system-id": "83",
    "platform-proxy": "am9pbmVhc3QtYXBw"
}
cookies = {
    "JSESSIONID": "5586872CB2EC06DEA6DC3B178E24FBD9"
}

class VideoDecryptor:
    # 视频解密器类

    @staticmethod
    def hash_md5(string):
        # 使用MD5算法生成哈希值
        return hashlib.md5(string.encode()).hexdigest()

    @staticmethod
    def pad(s):
        # 填充函数，用于AES加密
        return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

    @staticmethod
    def unpad(s):
        # 删除填充字符
        return s[:-ord(s[len(s) - 1:])]

    @staticmethod
    def aes_cbc_decrypt(key, iv, data):
        # AES-CBC解密
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(data)
        return VideoDecryptor.unpad(decrypted_data)

    def decrypt_video_json(self, vid, encrypted_json_body_hex):
        # 解密视频json数据
        md5_hash = self.hash_md5(vid)
        key = md5_hash[:16].encode()
        iv = md5_hash[16:].encode()
        encrypted_data_bytes = bytes.fromhex(encrypted_json_body_hex)
        decrypted_data = self.aes_cbc_decrypt(key, iv, encrypted_data_bytes)
        decrypted_str = base64.b64decode(decrypted_data).decode('utf-8')
        return json.loads(decrypted_str)

class M3U8Processor:
    # M3U8处理器类

    def __init__(self, decryptor):
        # 初始化，传入VideoDecryptor实例
        self.decryptor = decryptor

    def process_m3u8(self, m3u8url, seed_const, token):
        # 处理M3U8文件
        m3u8content = requests.get(m3u8url).text
        rem = re.search(r'URI="([^"]+)"', m3u8content, re.M | re.I)
        if not rem:
            print("m3u8 key url not found")
            return
        m3u8keyurl = rem.group(1).strip() + f"?token={token}"
        try:
            m3u8key = requests.get(m3u8keyurl).content
            print("m3u8key -->",m3u8key,len(m3u8key))
        except requests.RequestException as e:
            print(f"Error fetching m3u8 key: {e}")
            return
        if len(m3u8key) == 32:
            aeskey = self.decryptor.hash_md5(str(seed_const))[:16].encode()
            iv = b'\x01\x02\x03\x05\x07\x0B\x0D\x11\x13\x17\x1D\x07\x05\x03\x02\x01'
            m3u8key = self.decryptor.aes_cbc_decrypt(aeskey, iv, m3u8key)
        return m3u8key

class M3U8Downloader:
    # M3U8下载器类

    def __init__(self, m3u8_url, cipher, temp_folder=None, output_folder="output"):
        # 初始化下载器
        self.m3u8_url = m3u8_url
        self.cipher = cipher
        self.temp_folder = temp_folder if temp_folder else f"temp_{uuid.uuid4()}"
        self.output_folder = output_folder
        if not os.path.exists(self.temp_folder):
            os.makedirs(self.temp_folder)
        if not os.path.exists(self.output_folder):
            os.makedirs(self.output_folder)

    def download(self, outputname):
        # 下载视频
        response = requests.get(self.m3u8_url)
        m3u8_obj = m3u8.loads(response.text)
        self.download_ts_files(m3u8_obj.segments)
        self.merge_videos(outputname)

    def download_ts_files(self, ts_segments):
        # 下载TS文件
        for i, segment in enumerate(ts_segments):
            response = requests.get(segment.uri)
            file_name = f"{self.temp_folder}/segment_{i:05d}.ts"
            with open(file_name, 'wb') as f:
                for chunk in response.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(self.cipher.decrypt(chunk))

    def merge_videos(self, outputname):
        # 合并视频
        ts_files = sorted(glob.glob(f'{self.temp_folder}/*.ts'))
        with open(f'{self.output_folder}/{outputname}.mp4', 'wb') as merged:
            for ts_file in ts_files:
                with open(ts_file, 'rb') as f:
                    shutil.copyfileobj(f, merged)
        # 清理临时文件夹
        shutil.rmtree(self.temp_folder)

    def download_thread(self, outputname):
        # 使用线程下载视频
        try:
            self.download(outputname)
        except Exception as e:
            print(f"Error in downloading {outputname}: {e}")

def download_video(vid, title, courseId, headers, cookies):
    # 下载视频函数
    # 获取body加密数据
    jsondataurl = f"http://player.polyv.net/videojson/{vid}.json"
    encrypted_json_body_hex = requests.get(url=jsondataurl, headers=headers, cookies=cookies, verify=False).json()
    tokenurl = f"http://vip.fjzsbks.com/api/learning/ext/courseDetails/play/{courseId}"
    token = requests.get(tokenurl, headers=headers, cookies=cookies, verify=False).json()["data"]["token"]
    # 解密body数据 seed_const 字段用于后续的key加密
    decryptor = VideoDecryptor()
    decrypted_json = decryptor.decrypt_video_json(vid, encrypted_json_body_hex["body"])
    # 解密key
    processor = M3U8Processor(decryptor)
    m3u8url = f"http://hls.videocc.net/518495b053/9/{vid[0:32]}_1.m3u8"
    m3u8key = processor.process_m3u8(m3u8url, decrypted_json["seed_const"], token)
    cipher = AES.new(m3u8key, AES.MODE_CBC, "0000000000000000".encode())
    # 为每个下载任务创建独立的临时目录
    temp_folder = f"temp_{uuid.uuid4()}"  
    downloader = M3U8Downloader(m3u8url, cipher=cipher, temp_folder=temp_folder)
    downloader.download_thread(title)

def main():
    # 主函数
    # 指定下载哪个课程
    url = "http://vip.fjzsbks.com/api/learning/ext/courseDetails/courseTableInfo/3138"
    response = requests.get(url, headers=headers, cookies=cookies, verify=False).json()

    threads = []
    # 使用 ThreadPoolExecutor 来管理线程
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        #获取课程下面的全部分支
        for items in response["data"]["courseList"]:
            # vid用于后面加密
            vid = items["videoId"]
            # 视频名字
            title = items["title"]
            # m3u8数据
            courseId = items["courseId"]

            # 向线程池提交下载任务
            futures.append(executor.submit(download_video, vid, title, courseId, headers, cookies))

        # 等待所有任务完成
        for future in concurrent.futures.as_completed(futures):
            future.result()  # 这里可以处理每个任务的返回值或异常

if __name__ == "__main__":
    main()
