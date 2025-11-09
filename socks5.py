import subprocess
import sys
import tempfile
import os
import shutil
import hashlib
import json
import time
from datetime import datetime
import getpass
import threading



# --- 依赖检查 ---
try:
    from tqdm import tqdm
except ImportError:
    print("错误: 缺少 'tqdm' 库。请运行 'pip install tqdm' 进行安装。")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("错误: 缺少 'requests' 库。请运行 'pip install requests' 进行安装。")
    sys.exit(1)


# --- GO 语言核心代码 1: SOCKS5 协议验证器 (快速) ---
GO_SOURCE_CODE_PROTOCOL_VERIFIER = r'''
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

func verifyProtocol(target string, timeout time.Duration, results chan<- string) {
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		results <- ""
		return
	}
	defer conn.Close()

	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		results <- ""
		return
	}
	resp := make([]byte, 2)
	conn.SetReadDeadline(time.Now().Add(timeout))
	n, err := conn.Read(resp)
	if err == nil && n == 2 && resp[0] == 0x05 && resp[1] == 0x00 {
		results <- target
	} else {
		results <- ""
	}
}

func main() {
	inputFile := flag.String("inputFile", "", "输入的原始代理文件")
	outputFile := flag.String("outputFile", "", "输出验证后可用代理的文件")
	threads := flag.Int("threads", 100, "并发线程数")
	timeout := flag.Int("timeout", 10, "连接超时时间 (秒)")
	flag.Parse()

	if *inputFile == "" || *outputFile == "" { os.Exit(1) }
	file, _ := os.Open(*inputFile); defer file.Close(); scanner := bufio.NewScanner(file); var targets []string
	for scanner.Scan() { targets = append(targets, strings.TrimSpace(scanner.Text())) }
	
	total := len(targets)
	fmt.Fprintf(os.Stderr, "开始对 %d 个目标进行 SOCKS5 协议验证...\n", total)

	outFile, _ := os.Create(*outputFile); defer outFile.Close()
	writer := bufio.NewWriter(outFile)
	
	results := make(chan string, *threads)
	var writerWg sync.WaitGroup
	var validCount int
	writerWg.Add(1)
	go func() {
		defer writerWg.Done()
		for r := range results {
			if r != "" {
				validCount++
				fmt.Println(r) // Keep printing to stdout for immediate feedback
				fmt.Fprintln(writer, r)
				writer.Flush()
			}
		}
	}()

	var workerWg sync.WaitGroup; sem := make(chan struct{}, *threads)
	for _, target := range targets {
		if target == "" { continue }
		workerWg.Add(1); sem <- struct{}{}; go func(t string) {
			defer workerWg.Done()
			verifyProtocol(t, time.Duration(*timeout)*time.Second, results)
			<-sem
		}(target)
	}
	workerWg.Wait(); close(results); writerWg.Wait()

	fmt.Fprintf(os.Stderr, "验证完成！从 %d 个目标中发现 %d 个响应 SOCKS5 协议的服务器。\n", total, validCount)
	fmt.Fprintf(os.Stderr, "结果已实时保存至: %s\n", *outputFile)
}
'''

# --- GO 语言核心代码 2: SOCKS5 深度连接验证器 (用于公共代理) ---
GO_SOURCE_CODE_DEEP_VERIFIER = r'''
package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

func verifyProxyConnectivity(target string, timeout time.Duration, results chan<- string) {
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil { results <- ""; return }; defer conn.Close()
	_, err = conn.Write([]byte{0x05, 0x01, 0x00}); if err != nil { results <- ""; return }
	resp := make([]byte, 2); conn.SetReadDeadline(time.Now().Add(timeout)); n, err := conn.Read(resp)
	if err != nil || n != 2 || resp[0] != 0x05 || resp[1] != 0x00 { results <- ""; return }

	destHost := "example.com"; destPort := 80
	req := []byte{0x05, 0x01, 0x00, 0x03}; req = append(req, byte(len(destHost))); req = append(req, destHost...)
	portBytes := make([]byte, 2); binary.BigEndian.PutUint16(portBytes, uint16(destPort)); req = append(req, portBytes...)
	_, err = conn.Write(req); if err != nil { results <- ""; return }

	reply := make([]byte, 10); conn.SetReadDeadline(time.Now().Add(timeout)); n, err = conn.Read(reply)
	if err != nil || n < 4 { results <- ""; return }
	if reply[1] == 0x00 { results <- target } else { results <- "" }
}

func main() {
	inputFile := flag.String("inputFile", "", ""); outputFile := flag.String("outputFile", "", ""); threads := flag.Int("threads", 100, ""); timeout := flag.Int("timeout", 10, ""); flag.Parse()
	if *inputFile == "" || *outputFile == "" { os.Exit(1) }
	file, _ := os.Open(*inputFile); defer file.Close(); scanner := bufio.NewScanner(file); var targets []string
	for scanner.Scan() { targets = append(targets, strings.TrimSpace(scanner.Text())) }
	
	total := len(targets)
	fmt.Fprintf(os.Stderr, "开始对 %d 个代理进行深度连接验证...\n", total)

	outFile, _ := os.Create(*outputFile); defer outFile.Close()
	writer := bufio.NewWriter(outFile)
	
	results := make(chan string, *threads)
	var writerWg sync.WaitGroup
	var validCount int
	writerWg.Add(1)
	go func() {
		defer writerWg.Done()
		for r := range results {
			if r != "" {
				validCount++
				fmt.Println(r)
				fmt.Fprintln(writer, r)
				writer.Flush()
			}
		}
	}()

	var workerWg sync.WaitGroup; sem := make(chan struct{}, *threads)
	for _, target := range targets {
		if target == "" { continue }
		workerWg.Add(1); sem <- struct{}{}; go func(t string) {
			defer workerWg.Done()
			verifyProxyConnectivity(t, time.Duration(*timeout)*time.Second, results)
			<-sem
		}(target)
	}
	workerWg.Wait(); close(results); writerWg.Wait()

	fmt.Fprintf(os.Stderr, "验证完成！从 %d 个目标中发现 %d 个真正可用的代理。\n", total, validCount)
	fmt.Fprintf(os.Stderr, "结果已实时保存至: %s\n", *outputFile)
}
'''

# --- GO 语言核心代码 3: 全功能认证扫描器 (用于私有代理) ---
GO_SOURCE_CODE_SCANNER = r'''
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type Creds struct { Username string; Password string }

func checkProxyAuth(host, port string, creds Creds, timeout time.Duration) bool {
	target := fmt.Sprintf("%s:%s", host, port)
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil { return false }
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	// Request methods: NO AUTH (0x00), USER/PASS (0x02)
	_, err = conn.Write([]byte{0x05, 0x02, 0x00, 0x02})
	if err != nil { return false }
	
	reply := make([]byte, 2)
	_, err = conn.Read(reply)
	if err != nil || reply[0] != 0x05 { return false }

	switch reply[1] {
	case 0x00: // No Authentication Required
		return true
	case 0x02: // Username/Password
		if creds.Username == "" && creds.Password == "" { return false } // No point trying empty creds here
		userBytes, passBytes := []byte(creds.Username), []byte(creds.Password)
		req := append([]byte{0x01, byte(len(userBytes))}, userBytes...)
		req = append(req, byte(len(passBytes)))
		req = append(req, passBytes...)
		_, err = conn.Write(req)
		if err != nil { return false }
		authReply := make([]byte, 2)
		_, err = conn.Read(authReply)
		if err == nil && authReply[0] == 0x01 && authReply[1] == 0x00 {
			return true // User/pass auth success
		}
	}
	return false
}

func fileToLines(path string) ([]string, error) {
	file, err := os.Open(path); if err != nil { return nil, err }; defer file.Close(); var lines []string; scanner := bufio.NewScanner(file)
	for scanner.Scan() { lines = append(lines, strings.TrimSpace(scanner.Text())) }; return lines, scanner.Err()
}

func main() {
	proxyFile := flag.String("proxyFile", "", "File with proxies (host:port)")
	dictFile := flag.String("dictFile", "", "File with credentials (user:pass or user pass)")
	outputFile := flag.String("outputFile", "auth_success.txt", "Output file for all successful authentications")
	openFile := flag.String("openFile", "open_proxies.txt", "Output file for proxies with open authentication")
	threads := flag.Int("threads", 100, "Concurrency threads")
	timeout := flag.Int("timeout", 5, "Connection timeout (seconds)")
	flag.Parse()

	credentials := []Creds{{"", ""}} // Always check for NO AUTH
	if *dictFile != "" {
		dictLines, _ := fileToLines(*dictFile)
		for _, line := range dictLines {
			var cred Creds
			if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
				cred = Creds{parts[0], parts[1]}
			} else if parts = strings.Fields(line); len(parts) == 2 {
				cred = Creds{parts[0], parts[1]}
			}
			if cred.Username != "" || cred.Password != "" {
				credentials = append(credentials, cred)
			}
		}
	}
	
	proxies, _ := fileToLines(*proxyFile)
	fmt.Fprintf(os.Stderr, "开始对 %d 个代理使用 %d 组凭证进行认证扫描...\n", len(proxies), len(credentials))

	successCounts := make(map[string]int)
	var mu sync.Mutex

	outFile, _ := os.Create(*outputFile); defer outFile.Close()
	successWriter := bufio.NewWriter(outFile)
	defer successWriter.Flush()

	openOutFile, _ := os.Create(*openFile); defer openOutFile.Close()
	openWriter := bufio.NewWriter(openOutFile)
	defer openWriter.Flush()

	var wg sync.WaitGroup
	sem := make(chan struct{}, *threads)

	for _, proxy := range proxies {
		parts := strings.Split(proxy, ":")
		if len(parts) != 2 { continue }
		host, port := parts[0], parts[1]

		for _, cred := range credentials {
			wg.Add(1)
			sem <- struct{}{}
			go func(h, p string, c Creds) {
				defer wg.Done()
				defer func() { <-sem }()
				
				if checkProxyAuth(h, p, c, time.Duration(*timeout)*time.Second) {
					target := fmt.Sprintf("%s:%s", h, p)
					successMsg := fmt.Sprintf("[+] 成功: %s - 用户名: '%s' - 密码: '%s'", target, c.Username, c.Password)
					if c.Username == "" && c.Password == "" {
						successMsg = fmt.Sprintf("[+] 成功: %s (无需认证)", target)
					}
					
					fmt.Println(successMsg) // Print to console

					mu.Lock()
					// Write to main success file
					fmt.Fprintln(successWriter, successMsg)
					
					successCounts[target]++
					if successCounts[target] == 2 { // First time we detect it as open
						fmt.Fprintf(os.Stderr, "[!] 检测到开放代理: %s (接受多种凭证), 已记录至 %s\n", target, *openFile)
						fmt.Fprintln(openWriter, target)
						openWriter.Flush() // Write immediately
					}
					mu.Unlock()
					successWriter.Flush()
				}
			}(host, port, cred)
		}
	}
	wg.Wait()
	fmt.Fprintf(os.Stderr, "认证扫描完成。成功结果已保存至 %s, 开放代理已保存至 %s\n", *outputFile, *openFile)
}

'''

# --- Python 包装器 ---

COMPILED_BINARIES = {}
CACHE_DIR = ".socks5_toolkit_cache"
CONFIG_FILE = "config.json"

# --- 配置管理 ---
def load_config():
    if not os.path.exists(CONFIG_FILE):
        default_config = {"bot_token": "", "chat_id": "", "custom_id_key": "VPS", "custom_id_value": ""}
        save_config(default_config)
        return default_config
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {"bot_token": "", "chat_id": "", "custom_id_key": "VPS", "custom_id_value": ""}

def save_config(config):
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=4)

def handle_config_menu(config):
    while True:
        print_header("设置菜单")
        print(f"  [1] Bot Token:         {'*' * 10 if config.get('bot_token') else '未设置'}")
        print(f"  [2] Chat ID:           {config.get('chat_id') or '未设置'}")
        print(f"  [3] 自定义标识名:    {config.get('custom_id_key') or 'VPS'}")
        print(f"  [4] 自定义标识值:    {config.get('custom_id_value') or '未设置'}")
        print("\n  [b] 返回主菜单")
        
        choice = input("\n请选择要修改的项: ").lower()
        if choice == '1':
            config['bot_token'] = getpass.getpass("请输入新的 Telegram Bot Token (输入隐藏): ")
        elif choice == '2':
            config['chat_id'] = input("请输入新的 Chat ID: ")
        elif choice == '3':
            config['custom_id_key'] = input(f"请输入新的标识名 (当前: {config.get('custom_id_key', 'VPS')}): ")
        elif choice == '4':
            config['custom_id_value'] = input(f"请输入新的标识值 (当前: {config.get('custom_id_value')}): ")
        elif choice == 'b':
            break
        else:
            print("无效输入。")
            continue
        save_config(config)
        print("设置已保存！")

# --- 核心功能 ---
def print_header(title):
    print("\n" + "="*50); print(f"--- {title} ---"); print("="*50)

def get_validated_input(prompt, validation_func=lambda x: True, error_message="无效输入"):
    while True:
        user_input = input(prompt).strip()
        if validation_func(user_input): return user_input
        else: print(f"输入错误: {error_message}")

def validate_file_exists(path): return os.path.exists(path)
def validate_positive_integer(num_str): return num_str.isdigit() and int(num_str) > 0

def get_go_executable_path():
    go_exec = shutil.which("go")
    if go_exec: return go_exec
    common_paths = ["/usr/local/go/bin/go", "/usr/bin/go", "C:\\Go\\bin\\go.exe"]
    for path in common_paths:
        if os.path.exists(path): return path
    return None

def compile_go_binaries():
    global COMPILED_BINARIES
    go_executable = get_go_executable_path()
    if not go_executable:
        print("\n错误: 未找到 'go' 命令。请确保 Go 环境已正确安装并配置在系统 PATH 中。")
        return False

    os.makedirs(CACHE_DIR, exist_ok=True); print("正在检查Go核心程序...")
    sources = {
        "protocol_verifier": GO_SOURCE_CODE_PROTOCOL_VERIFIER,
        "deep_verifier": GO_SOURCE_CODE_DEEP_VERIFIER,
        "scanner": GO_SOURCE_CODE_SCANNER,
    }
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            for name, code in sources.items():
                current_hash = hashlib.sha256(code.encode('utf-8')).hexdigest()
                exe_name = f"{name}.exe" if sys.platform == "win32" else name
                output_path = os.path.join(CACHE_DIR, exe_name)
                hash_path = os.path.join(CACHE_DIR, f"{name}.hash")
                recompile = True
                if os.path.exists(output_path) and os.path.exists(hash_path):
                    with open(hash_path, 'r') as f: stored_hash = f.read()
                    if stored_hash == current_hash: recompile = False
                if recompile:
                    print(f"  - 正在编译 '{name}'...")
                    source_path = os.path.join(temp_dir, f"{name}.go")
                    with open(source_path, "w", encoding="utf-8") as f: f.write(code)
                    cmd = [go_executable, "build", "-o", output_path, source_path]
                    
                    build_env = os.environ.copy()
                    if "HOME" not in build_env and "USERPROFILE" not in build_env:
                        go_cache_path = os.path.join(temp_dir, "gocache_for_build")
                        os.makedirs(go_cache_path, exist_ok=True)
                        build_env["GOCACHE"] = go_cache_path
                        print(f"  - 提示: 未找到HOME/USERPROFILE，已临时设置GOCACHE: {go_cache_path}")
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, env=build_env)
                    if result.returncode != 0:
                         print(f"\nGo程序编译失败: {name}\n{result.stderr}")
                         return False

                    with open(hash_path, 'w') as f: f.write(current_hash)
                    print(f"  - '{name}' 编译完成。")
                else:
                    print(f"  - 使用缓存的 '{name}'。")
                COMPILED_BINARIES[name] = output_path
        print("Go核心程序准备就绪。"); return True
    except Exception as e: print(f"\n发生未知错误: {e}"); return False


# ... (脚本的其他部分保持不变) ...

def run_go_executable(executable_name, args_list, pbar_desc="已找到"):
    executable_path = COMPILED_BINARIES.get(executable_name)
    if not executable_path:
        print(f"错误: 未找到 '{executable_name}' 程序。")
        return

    try:
        cmd = [executable_path] + args_list
        print("\n--- 正在执行 Go 高性能核心 (健壮模式) ---")
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding='utf-8', errors='replace'
        )

        # 为 stdout 和 stderr 创建独立的读取线程，防止死锁
        def reader_thread(pipe, output_list, pbar=None):
            try:
                for line in iter(pipe.readline, ''):
                    if line:
                        output_list.append(line)
                        if pbar:
                            # 只有主输出才更新进度条
                            pbar.update(1)
                        else:
                            # 错误流直接打印
                            print(line.strip(), file=sys.stderr)
            finally:
                pipe.close()
        
        stdout_output = []
        stderr_output = []

        if "verifier" in executable_name:
            with tqdm(desc=pbar_desc, unit=" 个", dynamic_ncols=True) as pbar:
                stdout_thread = threading.Thread(target=reader_thread, args=(process.stdout, stdout_output, pbar))
                stderr_thread = threading.Thread(target=reader_thread, args=(process.stderr, stderr_output, None))
                
                stdout_thread.start()
                stderr_thread.start()
                
                stdout_thread.join() # 等待线程结束
                stderr_thread.join()
        else: # 认证扫描器模式，直接打印
            def print_pipe(pipe):
                try:
                    for line in iter(pipe.readline, ''):
                        print(line.strip())
                finally:
                    pipe.close()

            stdout_thread = threading.Thread(target=print_pipe, args=(process.stdout,))
            stderr_thread = threading.Thread(target=print_pipe, args=(process.stderr,))
            stdout_thread.start()
            stderr_thread.start()
            stdout_thread.join()
            stderr_thread.join()

        process.wait() # 确保子进程完全退出

        if "verifier" in executable_name:
            print("\n--- 任务执行完毕 ---")
            
    except Exception as e:
        print(f"执行Go程序时出错: {e}")


def create_dict_from_user_pass_files(temp_dir):
    print_header("模式: username.txt + password.txt")
    user_file = get_validated_input("请输入用户名文件 (username.txt): ", validate_file_exists, "文件不存在。")
    pass_file = get_validated_input("请输入密码文件 (password.txt): ", validate_file_exists, "文件不存在。")

    try:
        with open(user_file, 'r', encoding='utf-8', errors='ignore') as f_user:
            users = [line.strip() for line in f_user if line.strip()]
        with open(pass_file, 'r', encoding='utf-8', errors='ignore') as f_pass:
            passwords = [line.strip() for line in f_pass if line.strip()]
        
        temp_dict_path = os.path.join(temp_dir, 'combined_dict.txt')
        with open(temp_dict_path, 'w', encoding='utf-8') as f_out:
            for user in users:
                for password in passwords:
                    f_out.write(f"{user}:{password}\n")
        print(f"已生成 {len(users) * len(passwords)} 条密码组合到临时文件。")
        return temp_dict_path
    except Exception as e:
        print(f"创建密码本时出错: {e}")
        return None

def create_dict_from_same_user_pass(temp_dir):
    print_header("模式: 用户名和密码相同")
    wordlist_file = get_validated_input("请输入单词本文件 (例如: user.txt): ", validate_file_exists, "文件不存在。")
    try:
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f_in:
            words = [line.strip() for line in f_in if line.strip()]
        
        temp_dict_path = os.path.join(temp_dir, 'same_user_pass_dict.txt')
        with open(temp_dict_path, 'w', encoding='utf-8') as f_out:
            for word in words:
                f_out.write(f"{word}:{word}\n")
        print(f"已根据 {len(words)} 个单词生成同名密码组合到临时文件。")
        return temp_dict_path
    except Exception as e:
        print(f"创建密码本时出错: {e}")
        return None

def handle_auth_scan(output_dir):
    dict_file_path = None
    temp_dir_for_dict = tempfile.mkdtemp()

    try:
        while True:
            print_header("私有代理认证扫描 - 密码本模式选择")
            print("  [1] 组合模式 (username.txt + password.txt)")
            print("  [2] 同名模式 (username = password)")
            print("  [3] 标准模式 (单文件 user:pass 或 user pass)")
            print("  [b] 返回上级菜单")
            choice = input("\n请选择密码本模式: ").lower()

            if choice == '1':
                dict_file_path = create_dict_from_user_pass_files(temp_dir_for_dict)
                break
            elif choice == '2':
                dict_file_path = create_dict_from_same_user_pass(temp_dir_for_dict)
                break
            elif choice == '3':
                print_header("模式: 标准密码本")
                dict_file_path = get_validated_input("请输入密码本路径 (user:pass格式): ", validate_file_exists, "文件不存在。")
                break
            elif choice == 'b':
                return
            else:
                print("无效输入。")
        
        if not dict_file_path:
            print("未能生成或指定密码本，任务取消。")
            return

        proxy_file = get_validated_input("请输入代理文件 (host:port): ", validate_file_exists, "文件不存在。")
        threads = get_validated_input("并发数 (默认100): ", lambda x: x=="" or validate_positive_integer(x), "") or "100"
        timeout = get_validated_input("超时(秒, 默认5): ", lambda x: x=="" or validate_positive_integer(x), "") or "5"
        
        base, ext = os.path.splitext(os.path.basename(proxy_file))
        success_output_file = os.path.join(output_dir, f"{base}_auth_success.txt")
        open_proxy_output_file = os.path.join(output_dir, f"{base}_open_proxies.txt")

        print("\n扫描结果将实时打印在控制台。")
        print(f"所有成功认证的结果将保存到: {success_output_file}")
        print(f"检测到的开放代理将保存到: {open_proxy_output_file}")
        
        cmd_args = [
            "-proxyFile", proxy_file,
            "-threads", threads,
            "-timeout", timeout,
            "-dictFile", dict_file_path,
            "-outputFile", success_output_file,
            "-openFile", open_proxy_output_file
        ]
        
        run_go_executable("scanner", cmd_args)
        
    finally:
        shutil.rmtree(temp_dir_for_dict) # 清理临时目录和里面的文件

# --- 其他任务与主菜单 ---
def format_duration(seconds):
    secs = int(seconds)
    mins, secs = divmod(secs, 60)
    return f"{mins} 分 {secs} 秒"

def send_telegram_notification(config, file_path, total_targets, duration_seconds):
    token = config.get("bot_token")
    chat_id = config.get("chat_id")
    
    timestamp = datetime.now().strftime("%Y%m%d-%H%M")
    new_filename = f"Socks5-{os.path.basename(file_path)}-{timestamp}.txt"
    
    custom_key = config.get('custom_id_key', 'VPS')
    custom_value = config.get('custom_id_value', '未设置')
    
    caption = (
        f"{custom_key}: {custom_value}\n"
        f"总目标数: {total_targets}\n"
        f"总用时: {format_duration(duration_seconds)}\n"
        f"任务结果: {new_filename}"
    )
    
    url = f"https://api.telegram.org/bot{token}/sendDocument"
    try:
        print("正在发送文件到 Telegram...")
        with open(file_path, 'rb') as f:
            files = {'document': (new_filename, f)}
            data = {'chat_id': chat_id, 'caption': caption}
            response = requests.post(url, files=files, data=data, timeout=60)
        
        response.raise_for_status()
        result = response.json()
        if result.get("ok"): print("文件发送成功！")
        else: print(f"发送失败: {result.get('description', '未知错误')}")
    except requests.exceptions.RequestException as e: print(f"发送时发生网络错误: {e}")
    except Exception as e: print(f"发生未知错误: {e}")

def prompt_and_send_telegram(config, file_path, total_targets, duration_seconds):
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        print("\n结果文件为空或不存在，无需发送。")
        return
    
    if not config.get("bot_token") or not config.get("chat_id"):
        print("\n[!] Telegram 未配置。请在主菜单 -> [3] 设置 中配置 Bot Token 和 Chat ID 后再发送。")
        return

    choice = input(f"\n是否将结果文件 '{os.path.basename(file_path)}' 发送到 Telegram? (y/n): ").lower()
    if choice == 'y':
        send_telegram_notification(config, file_path, total_targets, duration_seconds)

def execute_scan_task(config, output_dir, mode):
    task_map = {
        "protocol": {
            "header": "验证Socks5协议 (快速)", "desc": "此模式只检查目标是否响应SOCKS5握手，不测试其可用性。",
            "threads_prompt": "并发数 (默认500): ", "threads_default": "500", "timeout_prompt": "超时(秒, 推荐5): ", "timeout_default": "5",
            "output_suffix": "_protocol_verified"
        },
        "deep": {
            "header": "扫描公共代理 (无认证)", "desc": "此功能将深度验证代理，确保其不仅是SOCKS5服务，还能实际连接到目标网站。",
            "threads_prompt": "并发数 (默认200): ", "threads_default": "200", "timeout_prompt": "超时(秒, 推荐10): ", "timeout_default": "10",
            "output_suffix": "_deep_verified"
        }
    }
    task = task_map[mode]
    print_header(task["header"]); print(task["desc"])
    
    input_file = get_validated_input("请输入原始目标文件路径: ", validate_file_exists, "文件不存在。")
    
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            total_targets = sum(1 for line in f if line.strip())
    except Exception as e: print(f"读取文件时出错: {e}"); return
        
    if total_targets == 0: print("输入文件为空，任务取消。"); return

    threads = get_validated_input(task["threads_prompt"], lambda x: x=="" or validate_positive_integer(x), "") or task["threads_default"]
    timeout = get_validated_input(task["timeout_prompt"], lambda x: x=="" or validate_positive_integer(x), "") or task["timeout_default"]
    
    base, ext = os.path.splitext(os.path.basename(input_file))
    output_file_path = os.path.join(output_dir, f"{base}{task['output_suffix']}{ext}")
    print(f"结果将实时保存至: {output_file_path}")
    
    cmd_args = ["-inputFile", input_file, "-outputFile", output_file_path, "-threads", threads, "-timeout", timeout]
    
    start_time = time.time()
    run_go_executable(mode+"_verifier", cmd_args) # "protocol_verifier" or "deep_verifier"
    end_time = time.time()
    
    duration = end_time - start_time
    prompt_and_send_telegram(config, output_file_path, total_targets, duration)

def handle_discover_usability(config, output_dir):
    while True:
        print_header("发现可用Socks5 (深度)")
        print("  [1] 扫描公共代理 (无认证)")
        print("  [2] 扫描私有代理 (需密码本)")
        print("  [b] 返回主菜单")
        choice = input("\n请选择扫描类型: ").lower()
        if choice == '1': execute_scan_task(config, output_dir, "deep"); break
        elif choice == '2': handle_auth_scan(output_dir); break
        elif choice == 'b': break
        else: print("无效输入，请重新选择。")

def main():
    if not compile_go_binaries(): sys.exit(1)
    
    config = load_config()
    session_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_dir = f"toolkit_session_{session_timestamp}"
    os.makedirs(output_dir, exist_ok=True)
    
    print("\n" + "*"*60); print(" " * 15 + "SOCKS5 验证与发现工具 (配置版)"); print(f"--- 本次会话所有输出文件将保存在: '{output_dir}' 目录 ---")
    print(f"--- 配置文件: '{CONFIG_FILE}', Go核心缓存: '{CACHE_DIR}' ---"); print("*"*60)

    while True:
        print("\n--- 主菜单 ---")
        print("  [1] 验证Socks5协议 (快速初筛)"); print("  [2] 发现可用Socks5 (深度验证)"); print("  [3] 设置"); print("  [4] 退出程序")
        choice = input("\n请输入您的选择 [1-4]: ")
        if choice == '1': execute_scan_task(config, output_dir, "protocol")
        elif choice == '2': handle_discover_usability(config, output_dir)
        elif choice == '3': handle_config_menu(config)
        elif choice == '4': print("感谢使用，再见！"); break
        else: print("无效的输入。")
        input("\n按 Enter 键返回主菜单...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n程序被用户中断。")
    except Exception as e:
        print(f"\n发生未捕获的严重错误: {e}")
    finally:
        print("程序退出。")
