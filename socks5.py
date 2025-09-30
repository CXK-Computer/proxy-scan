import subprocess
import sys
import tempfile
import os
import shutil
import re
import math
import atexit
from datetime import datetime

# --- GO 语言核心代码 1: SOCKS5 深度验证器 ---
# 这是工具唯一的筛选核心。它会完成握手和连接测试，一步到位。
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

// verifyProxyConnectivity 尝试通过代理连接到一个真实的目标，以验证其可用性
func verifyProxyConnectivity(target string, timeout time.Duration, results chan<- string) {
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		results <- "" // 连接失败
		return
	}
	defer conn.Close()

	// 步骤 1: 发送SOCKS5初始握手 (只关心无认证代理)
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		results <- ""
		return
	}
	resp := make([]byte, 2)
	conn.SetReadDeadline(time.Now().Add(timeout))
	n, err := conn.Read(resp)
	// 握手必须成功，且服务器必须选择“无需认证”(0x00)
	if err != nil || n != 2 || resp[0] != 0x05 || resp[1] != 0x00 {
		results <- "" // 握手失败或需要认证，不是我们寻找的目标
		return
	}

	// 步骤 2: 发送CONNECT命令到 example.com:80，模拟真实使用
	destHost := "example.com"
	destPort := 80
	req := []byte{0x05, 0x01, 0x00, 0x03} // VER, CMD, RSV, ATYP (Domain)
	req = append(req, byte(len(destHost)))
	req = append(req, destHost...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(destPort))
	req = append(req, portBytes...)

	_, err = conn.Write(req)
	if err != nil {
		results <- "" // 发送CONNECT命令失败
		return
	}

	// 步骤 3: 读取CONNECT命令的响应
	reply := make([]byte, 10) // 读取足够长的字节以获取状态
	conn.SetReadDeadline(time.Now().Add(timeout))
	n, err = conn.Read(reply)
	if err != nil || n < 4 {
		results <- "" // 响应不完整
		return
	}

	// 最终判断：只有当响应状态码(reply[1])为 0x00 (succeeded)时，才确认代理可用
	if reply[1] == 0x00 {
		results <- target // 深度验证成功！
	} else {
		results <- "" // 代理拒绝连接
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
	fmt.Printf("开始对 %d 个代理进行深度连接验证...\n", total)

	var wg sync.WaitGroup; results := make(chan string, total); sem := make(chan struct{}, *threads)
	for _, target := range targets {
		wg.Add(1); sem <- struct{}{}; go func(t string) {
			defer wg.Done()
			verifyProxyConnectivity(t, time.Duration(*timeout)*time.Second, results)
			<-sem
		}(target)
	}
	wg.Wait(); close(results)

	var validProxies []string
	for r := range results { if r != "" { validProxies = append(validProxies, r) } }

	outFile, _ := os.Create(*outputFile); defer outFile.Close()
	writer := bufio.NewWriter(outFile); for _, proxy := range validProxies { fmt.Fprintln(writer, proxy) }; writer.Flush()
		
	fmt.Printf("验证完成！从 %d 个目标中发现 %d 个真正可用的代理。\n", total, len(validProxies))
	fmt.Printf("结果已保存至: %s\n", *outputFile)
}
'''

# --- GO 语言核心代码 2: 全功能认证扫描器 ---
# (此部分保留，用于处理需要密码的私有代理)
GO_SOURCE_CODE_SCANNER = r'''
package main
import ( "bufio"; "flag"; "fmt"; "net"; "os"; "strings"; "sync"; "time" )
type Creds struct { Username string; Password string }
func checkProxyAuth(host string, port string, creds Creds, timeout time.Duration) {
	target := fmt.Sprintf("%s:%s", host, port); conn, err := net.DialTimeout("tcp", target, timeout); if err != nil { return }; defer conn.Close()
	_, err = conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); if err != nil { return }; reply := make([]byte, 2); _, err = conn.Read(reply)
	if err != nil || reply[0] != 0x05 { return }
	switch reply[1] {
	case 0x00: if creds.Username == "" && creds.Password == "" { fmt.Printf("[+] 成功: %s (无需认证)\n", target) }
	case 0x02:
		if creds.Username == "" && creds.Password == "" { return }
		userBytes, passBytes := []byte(creds.Username), []byte(creds.Password); req := append([]byte{0x01, byte(len(userBytes))}, userBytes...)
		req = append(req, byte(len(passBytes))); req = append(req, passBytes...); _, err = conn.Write(req); if err != nil { return }
		authReply := make([]byte, 2); _, err = conn.Read(authReply)
		if err == nil && authReply[0] == 0x01 && authReply[1] == 0x00 { fmt.Printf("[+] 成功: %s - 用户名: %s - 密码: %s\n", target, creds.Username, creds.Password) }
	}
}
func fileToLines(path string) ([]string, error) {
	file, err := os.Open(path); if err != nil { return nil, err }; defer file.Close(); var lines []string; scanner := bufio.NewScanner(file)
	for scanner.Scan() { lines = append(lines, scanner.Text()) }; return lines, scanner.Err()
}
func main() {
	proxyFile := flag.String("proxyFile", "", ""); dictFile := flag.String("dictFile", "", ""); threads := flag.Int("threads", 100, ""); timeout := flag.Int("timeout", 5, ""); flag.Parse()
	var credentials []Creds
	if *dictFile != "" {
		dictLines, _ := fileToLines(*dictFile)
		for _, line := range dictLines {
			parts := strings.Fields(line); if len(parts) == 2 { credentials = append(credentials, Creds{parts[0], parts[1]}) } else {
				parts = strings.SplitN(line, ":", 2); if len(parts) == 2 { credentials = append(credentials, Creds{parts[0], parts[1]}) }
			}
		}
	} else { credentials = append(credentials, Creds{"", ""}) }
	proxies, _ := fileToLines(*proxyFile); var wg sync.WaitGroup; sem := make(chan struct{}, *threads)
	for _, proxy := range proxies {
		parts := strings.Split(proxy, ":"); if len(parts) != 2 { continue }
		for _, cred := range credentials {
			wg.Add(1); sem <- struct{}{}; go func(h, p string, c Creds) {
				defer wg.Done(); defer func(){ <-sem }(); checkProxyAuth(h, p, c, time.Duration(*timeout)*time.Second)
			}(parts[0], parts[1], cred)
		}
	}
	wg.Wait()
}
'''

# --- Python 包装器 (终极版) ---

COMPILED_BINARIES = {}
TEMP_DIR = None

def print_header(title):
    print("\n" + "="*50); print(f"--- {title} ---"); print("="*50)

def get_validated_input(prompt, validation_func, error_message):
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

def setup_go_environment(temp_dir):
    env = os.environ.copy()
    if "HOME" not in env or not env["HOME"]: env["HOME"] = temp_dir
    gocache_path = os.path.join(temp_dir, ".gocache")
    os.makedirs(gocache_path, exist_ok=True)
    env["GOCACHE"] = gocache_path
    return env

def compile_go_binaries():
    global TEMP_DIR, COMPILED_BINARIES
    go_executable = get_go_executable_path()
    if not go_executable: print("\n错误: 未找到 'go' 命令。"); sys.exit(1)
    
    try:
        TEMP_DIR = tempfile.mkdtemp(prefix="socks5_toolkit_build_")
        atexit.register(cleanup_temp_dir)
        print("正在后台预编译Go核心程序...")
        sources = {
            "scanner": GO_SOURCE_CODE_SCANNER,
            "verifier": GO_SOURCE_CODE_DEEP_VERIFIER,
        }
        for name, code in sources.items():
            source_path = os.path.join(TEMP_DIR, f"{name}.go")
            exe_name = f"{name}.exe" if sys.platform == "win32" else name
            output_path = os.path.join(TEMP_DIR, exe_name)
            with open(source_path, "w", encoding="utf-8") as f: f.write(code)
            cmd = [go_executable, "build", "-o", output_path, source_path]
            subprocess.run(cmd, env=setup_go_environment(TEMP_DIR), check=True, capture_output=True)
            COMPILED_BINARIES[name] = output_path
        print("预编译完成。")
        return True
    except (subprocess.CalledProcessError, Exception) as e:
        print(f"\nGo程序编译失败: {e}"); cleanup_temp_dir(); return False

def cleanup_temp_dir():
    global TEMP_DIR
    if TEMP_DIR and os.path.exists(TEMP_DIR): shutil.rmtree(TEMP_DIR)

def run_go_executable(executable_name, args_list):
    executable_path = COMPILED_BINARIES.get(executable_name)
    if not executable_path: print(f"错误: 未找到 '{executable_name}' 程序。"); return
    try:
        cmd = [executable_path] + args_list
        print("\n--- 正在执行 Go 高性能核心 ---")
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding='utf-8', errors='replace'
        )
        for line in iter(process.stdout.readline, ''): print(line.strip())
        process.wait()
        print("--- 任务执行完毕 ---")
    except Exception as e: print(f"执行Go程序时出错: {e}")

def ask_and_split_file(input_path, output_dir):
    choice = input(f"文件 '{os.path.basename(input_path)}' 是否需要分割成小文件再处理? (y/n): ").lower()
    if choice != 'y': return [input_path]
    
    lines_per_file_str = get_validated_input("每个小文件行数 (默认1000): ", lambda x: x=="" or validate_positive_integer(x), "") or "1000"
    try:
        with open(input_path, 'r', encoding='utf-8') as f: lines = f.readlines()
        if not lines: print("文件为空。"); return [input_path]
        
        total_lines, lines_per_file = len(lines), int(lines_per_file_str)
        if total_lines <= lines_per_file: print("文件行数不足，无需分割。"); return [input_path]

        num_files = math.ceil(total_lines / lines_per_file)
        print(f"\n总计 {total_lines} 行，将被分割成 {num_files} 个文件。")
        file_base, file_ext = os.path.splitext(os.path.basename(input_path))
        
        new_file_paths = []
        for i in range(num_files):
            output_path = os.path.join(output_dir, f"{file_base}_part_{i+1}{file_ext}")
            with open(output_path, 'w', encoding='utf-8') as f_out: f_out.writelines(lines[i*lines_per_file:(i+1)*lines_per_file])
            print(f"已生成文件: {output_path}")
            new_file_paths.append(output_path)
        return new_file_paths
    except Exception as e: print(f"处理文件时出错: {e}"); return [input_path]

def handle_deep_verification(output_dir):
    print_header("深度验证并查找可用代理")
    print("此功能将一步到位，从原始列表中找出真正可用的(无认证)公共代理。")
    input_file = get_validated_input("请输入原始代理文件路径: ", validate_file_exists, "文件不存在。")
    files_to_verify = ask_and_split_file(input_file, output_dir)
    threads = get_validated_input("并发数 (默认100): ", lambda x: x=="" or validate_positive_integer(x), "") or "100"
    timeout = get_validated_input("超时(秒, 推荐10): ", lambda x: x=="" or validate_positive_integer(x), "") or "10"
    for file_path in files_to_verify:
        print(f"\n--- 正在深度验证文件: {os.path.basename(file_path)} ---")
        base, ext = os.path.splitext(os.path.basename(file_path))
        output_file_path = os.path.join(output_dir, f"{base}_verified{ext}")
        print(f"验证通过的代理将保存至: {output_file_path}")
        cmd_args = ["-inputFile", file_path, "-outputFile", output_file_path, "-threads", threads, "-timeout", timeout]
        run_go_executable("verifier", cmd_args)

def handle_auth_scan(output_dir):
    print_header("认证扫描 (用于私有/付费代理)")
    proxy_file = get_validated_input("请输入需要认证的代理文件: ", validate_file_exists, "文件不存在。")
    dict_file = get_validated_input("请输入密码本文件路径: ", validate_file_exists, "文件不存在。")
    threads = get_validated_input("并发数 (默认100): ", lambda x: x=="" or validate_positive_integer(x), "") or "100"
    timeout = get_validated_input("超时(秒, 默认5): ", lambda x: x=="" or validate_positive_integer(x), "") or "5"
    cmd_args = ["-proxyFile", proxy_file, "-threads", threads, "-timeout", timeout, "-dictFile", dict_file]
    run_go_executable("scanner", cmd_args)

def main():
    if not compile_go_binaries(): sys.exit(1)
    session_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_dir = f"toolkit_session_{session_timestamp}"
    os.makedirs(output_dir, exist_ok=True)
    print("\n" + "*"*60)
    print(" " * 15 + "SOCKS5 深度验证工具 (终极版)")
    print(f"--- 本次会话所有输出文件将保存在: '{output_dir}' 目录 ---")
    print("*"*60)
    while True:
        print("\n--- 主菜单 ---")
        print("  [1] 深度验证并查找可用代理 (用于公开代理列表)")
        print("  [2] 认证扫描 (用于私有/付费代理)")
        print("  [3] 退出程序")
        choice = input("\n请输入您的选择 [1-3]: ")
        if choice == '1': handle_deep_verification(output_dir)
        elif choice == '2': handle_auth_scan(output_dir)
        elif choice == '3': print("感谢使用，再见！"); break
        else: print("无效的输入。")
        input("\n按 Enter 键返回主菜单...")

if __name__ == "__main__":
    main()
